//! X.509 plumbing shared by token, chain and revocation checks:
//! extension lookup, validity windows, signature verification and
//! CMS algorithm normalization.

use der::asn1::ObjectIdentifier;
use der::oid::AssociatedOid;
use der::referenced::OwnedToRef;
use der::{Any, Decode};
use std::fmt;
use std::time::SystemTime;
use x509_cert::Certificate;
use x509_cert::ext::Extensions;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Validity;
use x509_verify::{Message, Signature, VerifyInfo, VerifyingKey};

use super::oids::{
    ID_ECDSA_WITH_SHA_256, ID_ECDSA_WITH_SHA_384, ID_ECDSA_WITH_SHA_512,
    ID_RSA_ENCRYPTION, ID_SHA_256, ID_SHA_256_WITH_RSA_ENCRYPTION, ID_SHA_384,
    ID_SHA_384_WITH_RSA_ENCRYPTION, ID_SHA_512,
    ID_SHA_512_WITH_RSA_ENCRYPTION,
};
use super::tsp::is_absent_or_null_parameter;

// Single spelling of the boxed cause type carried by the error
// variants of this module tree.
pub type FailureCause = Box<dyn std::error::Error + Send + Sync>;

/// One RFC 5754 pairing: the signature algorithm identifier that
/// folds the given digest algorithm in.
struct AlgorithmPairing {
    digest: ObjectIdentifier,
    signature: ObjectIdentifier,
}

/// The RSA PKCS#1 v1.5 pairings of RFC 5754 §3.2.
const RSA_PAIRINGS: &[AlgorithmPairing] = &[
    AlgorithmPairing {
        digest: ID_SHA_256,
        signature: ID_SHA_256_WITH_RSA_ENCRYPTION,
    },
    AlgorithmPairing {
        digest: ID_SHA_384,
        signature: ID_SHA_384_WITH_RSA_ENCRYPTION,
    },
    AlgorithmPairing {
        digest: ID_SHA_512,
        signature: ID_SHA_512_WITH_RSA_ENCRYPTION,
    },
];

/// The ECDSA pairings of RFC 5754 §3.3.
const ECDSA_PAIRINGS: &[AlgorithmPairing] = &[
    AlgorithmPairing {
        digest: ID_SHA_256,
        signature: ID_ECDSA_WITH_SHA_256,
    },
    AlgorithmPairing {
        digest: ID_SHA_384,
        signature: ID_ECDSA_WITH_SHA_384,
    },
    AlgorithmPairing {
        digest: ID_SHA_512,
        signature: ID_ECDSA_WITH_SHA_512,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionError {
    /// One extension OID appears twice; the certificate's claims are
    /// ambiguous and nothing about it can be decided.
    Duplicate { oid: ObjectIdentifier },
    /// The extension is present but its value does not parse.
    Undecodable {
        oid: ObjectIdentifier,
        source: der::Error,
    },
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { oid } => {
                write!(formatter, "extension {oid} appears twice")
            }
            Self::Undecodable { oid, source } => {
                write!(formatter, "extension {oid} does not parse ({source})")
            }
        }
    }
}

impl std::error::Error for ExtensionError {}

/// One decoded extension, with the criticality flag callers must
/// judge alongside the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedExtension<DecodedValue> {
    pub critical: bool,
    pub value: DecodedValue,
}

/// Finds and decodes the unique extension of `DecodedValue`'s OID.
/// Absence is a plain `None`; a duplicate or an undecodable value is
/// an error, because either leaves the certificate's claim undecided.
///
/// The parameter mirrors how X.509 structures carry their extension
/// lists — as an optional field, where an absent list claims the
/// same nothing an absent extension does. Taking the `Option` keeps
/// that equivalence in one place instead of at every call site,
/// which all start from `extensions.as_ref()` on some TBS structure.
pub fn decode_extension<'a, DecodedValue>(
    extensions: Option<&'a Extensions>,
) -> Result<Option<DecodedExtension<DecodedValue>>, ExtensionError>
where
    DecodedValue: Decode<'a> + AssociatedOid,
{
    let mut found = None;
    for extension in extensions.into_iter().flatten() {
        if extension.extn_id != DecodedValue::OID {
            continue;
        }
        if found.is_some() {
            return Err(ExtensionError::Duplicate {
                oid: DecodedValue::OID,
            });
        }
        let value = DecodedValue::from_der(extension.extn_value.as_bytes())
            .map_err(|source| ExtensionError::Undecodable {
                oid: DecodedValue::OID,
                source,
            })?;
        found = Some(DecodedExtension {
            critical: extension.critical,
            value,
        });
    }
    Ok(found)
}

/// Whether the validity window contains the moment. Both bounds are
/// inclusive (RFC 5280 §4.1.2.5).
pub fn covers_moment(validity: &Validity, moment: SystemTime) -> bool {
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();
    not_before <= moment && moment <= not_after
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The BIT STRING carries unused bits, which no supported
    /// signature encoding produces.
    MalformedSignature,
    /// The algorithm or key type is outside the supported set.
    Unsupported { oid: ObjectIdentifier },
    /// The bytes fail cryptographic verification.
    Invalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSignature => {
                write!(formatter, "the signature bytes are malformed")
            }
            Self::Unsupported { oid } => write!(
                formatter,
                "signature or key algorithm {oid} is unsupported"
            ),
            Self::Invalid => {
                write!(formatter, "the signature does not verify")
            }
        }
    }
}

impl std::error::Error for SignatureError {}

/// A signature as the ASN.1 structures carry it: the declared
/// algorithm beside the signature bytes. X.509 callers unwrap their
/// BIT STRING first, CMS callers pass their OCTET STRING contents.
#[derive(Clone, Copy, Debug)]
pub struct RawSignature<'a> {
    pub algorithm: &'a AlgorithmIdentifierOwned,
    pub bytes: &'a [u8],
}

fn map_verify_error(cause: x509_verify::Error) -> SignatureError {
    match cause {
        x509_verify::Error::Verification => SignatureError::Invalid,
        x509_verify::Error::UnknownOid(oid) => {
            SignatureError::Unsupported { oid }
        }
        _ => SignatureError::MalformedSignature,
    }
}

/// Verifies that `signature` over `message` was produced by the key
/// the issuer certificate carries.
pub fn verify_issued_signature(
    message: &[u8],
    signature: &RawSignature<'_>,
    issuer: &Certificate,
) -> Result<(), SignatureError> {
    let key_info = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let key = VerifyingKey::new(key_info).map_err(map_verify_error)?;
    key.verify(VerifyInfo::new(
        Message::new(message),
        Signature::new(signature.algorithm, signature.bytes),
    ))
    .map_err(map_verify_error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizeError {
    UnsupportedSignatureAlgorithm {
        oid: ObjectIdentifier,
    },
    UnsupportedDigestAlgorithm {
        oid: ObjectIdentifier,
    },
    /// The digest the SignerInfo declares is not the one its
    /// signature algorithm folds in.
    DigestSignatureMismatch {
        digest: ObjectIdentifier,
        signature: ObjectIdentifier,
    },
    /// The signature algorithm carries parameters its specification
    /// forbids or leaves undefined.
    ForbiddenParameters {
        oid: ObjectIdentifier,
    },
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSignatureAlgorithm { oid } => {
                write!(formatter, "signature algorithm {oid} is unsupported")
            }
            Self::UnsupportedDigestAlgorithm { oid } => {
                write!(formatter, "digest algorithm {oid} is unsupported")
            }
            Self::DigestSignatureMismatch { digest, signature } => write!(
                formatter,
                "digest algorithm {digest} contradicts signature \
                 algorithm {signature}"
            ),
            Self::ForbiddenParameters { oid } => write!(
                formatter,
                "signature algorithm {oid} carries forbidden parameters"
            ),
        }
    }
}

impl std::error::Error for NormalizeError {}

fn folded_digest_of(
    signature_oid: ObjectIdentifier,
) -> Option<ObjectIdentifier> {
    RSA_PAIRINGS
        .iter()
        .chain(ECDSA_PAIRINGS)
        .find(|pairing| pairing.signature == signature_oid)
        .map(|pairing| pairing.digest)
}

/// Rewrites a CMS SignerInfo's (digest, signature) algorithm pair
/// into the single self-contained identifier signature dispatch
/// expects. CMS allows the signature field to name the bare key type
/// (`rsaEncryption`) with the digest split off; the pair is folded
/// back together here, and a pre-folded identifier is checked for
/// consistency against the declared digest instead.
pub fn normalize_cms_signature_algorithm(
    digest_oid: ObjectIdentifier,
    signature_algorithm: &AlgorithmIdentifierOwned,
) -> Result<AlgorithmIdentifierOwned, NormalizeError> {
    if signature_algorithm.oid == ID_RSA_ENCRYPTION {
        if !is_absent_or_null_parameter(&signature_algorithm.parameters) {
            return Err(NormalizeError::ForbiddenParameters {
                oid: signature_algorithm.oid,
            });
        }
        let combined = RSA_PAIRINGS
            .iter()
            .find(|pairing| pairing.digest == digest_oid)
            .map(|pairing| pairing.signature)
            .ok_or(NormalizeError::UnsupportedDigestAlgorithm {
                oid: digest_oid,
            })?;
        // RFC 4055 §5: sha*WithRSAEncryption parameters MUST be NULL
        return Ok(AlgorithmIdentifierOwned {
            oid: combined,
            parameters: Some(Any::null()),
        });
    }
    let folded_digest = folded_digest_of(signature_algorithm.oid).ok_or(
        NormalizeError::UnsupportedSignatureAlgorithm {
            oid: signature_algorithm.oid,
        },
    )?;
    if folded_digest != digest_oid {
        return Err(NormalizeError::DigestSignatureMismatch {
            digest: digest_oid,
            signature: signature_algorithm.oid,
        });
    }
    let is_rsa_pairing = RSA_PAIRINGS
        .iter()
        .any(|pairing| pairing.signature == signature_algorithm.oid);
    if is_rsa_pairing {
        if !is_absent_or_null_parameter(&signature_algorithm.parameters) {
            return Err(NormalizeError::ForbiddenParameters {
                oid: signature_algorithm.oid,
            });
        }
        return Ok(AlgorithmIdentifierOwned {
            oid: signature_algorithm.oid,
            parameters: Some(Any::null()),
        });
    }
    // RFC 5754 §3.3: ecdsa-with-SHA2 identifiers MUST omit parameters
    if signature_algorithm.parameters.is_some() {
        return Err(NormalizeError::ForbiddenParameters {
            oid: signature_algorithm.oid,
        });
    }
    Ok(AlgorithmIdentifierOwned {
        oid: signature_algorithm.oid,
        parameters: None,
    })
}

#[cfg(test)]
use super::oids;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::oids::ID_SHA_1;

    use super::*;

    fn algorithm_with_null(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        }
    }

    fn bare_algorithm(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    #[test]
    fn bare_rsa_folds_the_digest_into_the_identifier() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_512,
            &algorithm_with_null(ID_RSA_ENCRYPTION),
        );
        assert_eq!(
            normalized,
            Ok(algorithm_with_null(ID_SHA_512_WITH_RSA_ENCRYPTION))
        );
    }

    #[test]
    fn a_prefolded_rsa_identifier_passes_when_digests_agree() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_256,
            &bare_algorithm(ID_SHA_256_WITH_RSA_ENCRYPTION),
        );
        assert_eq!(
            normalized,
            Ok(algorithm_with_null(ID_SHA_256_WITH_RSA_ENCRYPTION))
        );
    }

    #[test]
    fn a_prefolded_identifier_contradicting_the_digest_is_refused() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_256,
            &bare_algorithm(ID_ECDSA_WITH_SHA_512),
        );
        assert_eq!(
            normalized,
            Err(NormalizeError::DigestSignatureMismatch {
                digest: ID_SHA_256,
                signature: ID_ECDSA_WITH_SHA_512,
            })
        );
    }

    #[test]
    fn ecdsa_identifiers_pass_through_without_parameters() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_512,
            &bare_algorithm(ID_ECDSA_WITH_SHA_512),
        );
        assert_eq!(normalized, Ok(bare_algorithm(ID_ECDSA_WITH_SHA_512)));
    }

    #[test]
    fn ecdsa_identifiers_with_parameters_are_refused() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_512,
            &algorithm_with_null(ID_ECDSA_WITH_SHA_512),
        );
        assert_eq!(
            normalized,
            Err(NormalizeError::ForbiddenParameters {
                oid: ID_ECDSA_WITH_SHA_512,
            })
        );
    }

    #[test]
    fn an_unknown_signature_algorithm_is_refused() {
        let dsa_with_sha1 = ObjectIdentifier::new_unwrap("1.2.840.10040.4.3");
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_256,
            &bare_algorithm(dsa_with_sha1),
        );
        assert_eq!(
            normalized,
            Err(NormalizeError::UnsupportedSignatureAlgorithm {
                oid: dsa_with_sha1,
            })
        );
    }

    #[test]
    fn bare_rsa_with_an_unsupported_digest_is_refused() {
        let normalized = normalize_cms_signature_algorithm(
            ID_SHA_1,
            &algorithm_with_null(ID_RSA_ENCRYPTION),
        );
        assert_eq!(
            normalized,
            Err(NormalizeError::UnsupportedDigestAlgorithm { oid: ID_SHA_1 })
        );
    }

    #[test]
    fn validity_bounds_are_inclusive_on_both_ends() {
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let validity = Validity {
            not_before: not_before.try_into().expect("in range"),
            not_after: not_after.try_into().expect("in range"),
        };
        assert!(covers_moment(&validity, not_before));
        assert!(covers_moment(&validity, not_after));
        assert!(!covers_moment(
            &validity,
            not_before - Duration::from_secs(1)
        ));
        assert!(!covers_moment(
            &validity,
            not_after + Duration::from_secs(1)
        ));
    }
}
