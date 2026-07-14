//! Certificate chain validation to a caller-supplied trust anchor,
//! judged at the token's genTime (stamping specification §7
//! check 3).
//!
//! The path logic is deliberately hand-rolled and small: RFC 5280's
//! full algorithm covers policy processing and name constraints this
//! tool has no use for, and the verifier's explainability (design
//! requirement N1) outweighs generality. Trust anchors are taken as
//! given — their own extensions are not judged, only their validity
//! window and their signatures over chain members.

use der::Encode;
use der::asn1::ObjectIdentifier;
use der::oid::AssociatedOid;
use std::fmt;
use std::time::SystemTime;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::{Certificate, Version};

use super::revocation::{self, RevocationSubject};
use super::x509::{
    ExtensionError, RawSignature, covers_moment, decode_extension,
    verify_issued_signature,
};

// Real TSA chains run two to four certificates deep; the bound only
// exists so that a hostile certificate pool cannot keep the walk
// alive indefinitely.
const MAX_CHAIN_LENGTH: usize = 8;

/// The extensions the chain walk evaluates. Any *other* extension
/// marked critical means the certificate demands processing this
/// implementation cannot give, so the walk fails closed (RFC 5280
/// §4.2).
const EVALUATED_EXTENSIONS: &[ObjectIdentifier] =
    &[BasicConstraints::OID, ExtendedKeyUsage::OID, KeyUsage::OID];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The certificate's validity window does not contain genTime.
    OutsideValidity {
        subject: String,
    },
    /// Only v3 certificates can carry the extensions the checks
    /// need; anything else is undecidable.
    UnsupportedVersion {
        subject: String,
    },
    UnknownCriticalExtension {
        subject: String,
        oid: ObjectIdentifier,
    },
    MalformedExtension {
        subject: String,
        source: ExtensionError,
    },
    /// The certificate does not re-encode, so its signature cannot
    /// even be checked.
    UnencodableCertificate {
        subject: String,
    },
    /// No supplied certificate both names the subject's issuer and
    /// validly signed it inside its own validity window.
    NoTrustedIssuer {
        subject: String,
    },
    ChainTooLong,
    /// The chosen issuer is not marked as a certificate authority.
    IssuerNotAuthority {
        issuer: String,
    },
    /// The chosen issuer's key usage rules out certificate signing.
    IssuerCannotSignCertificates {
        issuer: String,
    },
    /// The chosen issuer's path length constraint forbids a chain
    /// this deep.
    PathLengthExceeded {
        issuer: String,
    },
    Revocation(revocation::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideValidity { subject } => write!(
                formatter,
                "{subject} is not valid at the token's genTime"
            ),
            Self::UnsupportedVersion { subject } => {
                write!(formatter, "{subject} is not a v3 certificate")
            }
            Self::UnknownCriticalExtension { subject, oid } => write!(
                formatter,
                "{subject} carries unsupported critical extension {oid}"
            ),
            Self::MalformedExtension { subject, source } => write!(
                formatter,
                "{subject} carries a malformed extension ({source})"
            ),
            Self::UnencodableCertificate { subject } => {
                write!(formatter, "{subject} does not re-encode")
            }
            Self::NoTrustedIssuer { subject } => write!(
                formatter,
                "no trusted certificate validly issued {subject}"
            ),
            Self::ChainTooLong => write!(
                formatter,
                "the chain exceeds {MAX_CHAIN_LENGTH} certificates"
            ),
            Self::IssuerNotAuthority { issuer } => write!(
                formatter,
                "{issuer} is not marked as a certificate authority"
            ),
            Self::IssuerCannotSignCertificates { issuer } => write!(
                formatter,
                "{issuer}'s key usage does not allow certificate signing"
            ),
            Self::PathLengthExceeded { issuer } => write!(
                formatter,
                "{issuer}'s path length constraint forbids this chain"
            ),
            Self::Revocation(cause) => {
                write!(formatter, "revocation check failed: {cause}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Revocation(cause) => Some(cause),
            _ => None,
        }
    }
}

/// The trust material a chain may be built from: the anchors the
/// caller trusts axiomatically, the companion certificates available
/// as intermediates (token-embedded and LTV-supplied), and the CRL
/// snapshots revocation is judged against.
#[derive(Clone, Copy, Debug)]
pub struct TrustPool<'a> {
    pub anchors: &'a [Certificate],
    pub companions: &'a [Certificate],
    pub crls: &'a [CertificateList],
}

fn name_of(certificate: &Certificate) -> String {
    certificate.tbs_certificate.subject.to_string()
}

fn ensure_screened(certificate: &Certificate) -> Result<(), Error> {
    if certificate.tbs_certificate.version != Version::V3 {
        return Err(Error::UnsupportedVersion {
            subject: name_of(certificate),
        });
    }
    let extensions = certificate.tbs_certificate.extensions.iter().flatten();
    for extension in extensions {
        let is_judgeable = EVALUATED_EXTENSIONS.contains(&extension.extn_id);
        if extension.critical && !is_judgeable {
            return Err(Error::UnknownCriticalExtension {
                subject: name_of(certificate),
                oid: extension.extn_id,
            });
        }
    }
    Ok(())
}

/// The certificate one chain step seeks an issuer for, beside its
/// re-encoded TBS bytes — computed once per step, reused across
/// candidates. Bundling also keeps it apart from the candidate at
/// the call sites, where two bare certificates would invite a swap.
struct StepSubject<'a> {
    certificate: &'a Certificate,
    message: &'a [u8],
}

/// Whether `candidate` validly signed the step's subject. A failure
/// only disqualifies the candidate; trust decisions fall out of
/// which candidates remain.
fn is_signing_issuer(
    subject: &StepSubject<'_>,
    candidate: &Certificate,
) -> bool {
    let Some(signature_bytes) = subject.certificate.signature.as_bytes()
    else {
        return false;
    };
    candidate.tbs_certificate.subject
        == subject.certificate.tbs_certificate.issuer
        && verify_issued_signature(
            subject.message,
            &RawSignature {
                algorithm: &subject.certificate.signature_algorithm,
                bytes: signature_bytes,
            },
            candidate,
        )
        .is_ok()
}

fn ensure_issuer_fitness(
    issuer: &Certificate,
    intermediates_below: usize,
) -> Result<(), Error> {
    let malformed = |source| Error::MalformedExtension {
        subject: name_of(issuer),
        source,
    };
    let constraints = decode_extension::<BasicConstraints>(
        issuer.tbs_certificate.extensions.as_ref(),
    )
    .map_err(malformed)?;
    let Some(authority) = constraints.filter(|decoded| decoded.value.ca)
    else {
        return Err(Error::IssuerNotAuthority {
            issuer: name_of(issuer),
        });
    };
    let within_length_limit = authority
        .value
        .path_len_constraint
        .map(|limit| intermediates_below <= usize::from(limit))
        .unwrap_or(true);
    if !within_length_limit {
        return Err(Error::PathLengthExceeded {
            issuer: name_of(issuer),
        });
    }
    // RFC 5280 §4.2.1.3: keyCertSign is the bit that authorizes
    // signing certificates. An absent extension restricts nothing.
    let key_usage = decode_extension::<KeyUsage>(
        issuer.tbs_certificate.extensions.as_ref(),
    )
    .map_err(malformed)?;
    let grants_certificate_signing = key_usage
        .map(|decoded| decoded.value.key_cert_sign())
        .unwrap_or(true);
    if grants_certificate_signing {
        Ok(())
    } else {
        Err(Error::IssuerCannotSignCertificates {
            issuer: name_of(issuer),
        })
    }
}

/// Validates the chain from `signer` to one of the pool's trust
/// anchors, entirely at genTime: validity windows, issuer authority,
/// signatures, and revocation against the pool's CRL snapshots. The
/// verifier has no clock; a chain valid at genTime stays valid no
/// matter when it is examined.
pub fn validate_chain(
    signer: &Certificate,
    pool: &TrustPool<'_>,
    gen_time: SystemTime,
) -> Result<(), Error> {
    let mut current = signer;
    // Every pass below the first consumes exactly one companion
    // intermediate, so the pass number doubles as the count of
    // intermediates already sitting below the candidate issuer.
    for intermediates_below in 0..MAX_CHAIN_LENGTH {
        if !covers_moment(&current.tbs_certificate.validity, gen_time) {
            return Err(Error::OutsideValidity {
                subject: name_of(current),
            });
        }
        if pool.anchors.contains(current) {
            return Ok(());
        }
        ensure_screened(current)?;
        let message = current.tbs_certificate.to_der().map_err(|_| {
            Error::UnencodableCertificate {
                subject: name_of(current),
            }
        })?;
        let step_subject = StepSubject {
            certificate: current,
            message: &message,
        };
        let candidates = pool.anchors.iter().chain(pool.companions);
        let issuer = candidates
            .filter(|candidate| *candidate != current)
            .filter(|candidate| {
                covers_moment(&candidate.tbs_certificate.validity, gen_time)
            })
            .find(|candidate| is_signing_issuer(&step_subject, candidate))
            .ok_or_else(|| Error::NoTrustedIssuer {
                subject: name_of(current),
            })?;
        let issuer_is_anchor = pool.anchors.contains(issuer);
        if !issuer_is_anchor {
            ensure_issuer_fitness(issuer, intermediates_below)?;
        }
        revocation::ensure_unrevoked(
            &RevocationSubject {
                certificate: current,
                issuer,
                gen_time,
            },
            pool.crls,
        )
        .map_err(Error::Revocation)?;
        if issuer_is_anchor {
            return Ok(());
        }
        current = issuer;
    }
    Err(Error::ChainTooLong)
}

#[cfg(test)]
use super::test_pki;

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    use super::*;

    struct Intermediate {
        certificate: Certificate,
        key: SigningKey,
    }

    fn intermediate_under(
        issuer: &Certificate,
        issuer_key: &SigningKey,
        extensions: Vec<x509_cert::ext::Extension>,
    ) -> Intermediate {
        let key = test_pki::signing_key_from_seed(0x44);
        let certificate = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 5,
                issuer: issuer.tbs_certificate.subject.clone(),
                subject: test_pki::parse_name("CN=Tydence Test Mid"),
                key_info: test_pki::key_info_of(&key),
                validity: test_pki::standard_validity(),
                extensions,
            },
            issuer_key,
        );
        Intermediate { certificate, key }
    }

    fn tsa_under(
        issuer: &Certificate,
        issuer_key: &SigningKey,
    ) -> Certificate {
        test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 6,
                issuer: issuer.tbs_certificate.subject.clone(),
                subject: test_pki::parse_name(test_pki::TSA_NAME),
                key_info: test_pki::key_info_of(
                    &test_pki::signing_key_from_seed(0x55),
                ),
                validity: test_pki::standard_validity(),
                extensions: test_pki::tsa_extensions(),
            },
            issuer_key,
        )
    }

    fn crl_by(
        issuer: &Certificate,
        issuer_key: &SigningKey,
    ) -> CertificateList {
        test_pki::issue_crl(
            test_pki::standard_crl_blueprint(),
            issuer,
            issuer_key,
        )
    }

    #[test]
    fn a_direct_chain_to_the_anchor_validates() {
        let authority = test_pki::standard_authority();
        let anchors = [authority.root_certificate.clone()];
        let crls = [test_pki::standard_crl(&authority)];
        let verdict = validate_chain(
            &authority.tsa_certificate,
            &TrustPool {
                anchors: &anchors,
                companions: &[],
                crls: &crls,
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(verdict, Ok(()));
    }

    #[test]
    fn a_signer_that_is_itself_an_anchor_is_trusted_directly() {
        let authority = test_pki::standard_authority();
        let anchors = [authority.tsa_certificate.clone()];
        let verdict = validate_chain(
            &authority.tsa_certificate,
            &TrustPool {
                anchors: &anchors,
                companions: &[],
                crls: &[],
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(verdict, Ok(()));
    }

    #[test]
    fn a_chain_through_an_intermediate_validates() {
        let authority = test_pki::standard_authority();
        let intermediate = intermediate_under(
            &authority.root_certificate,
            &authority.root_key,
            test_pki::ca_extensions(),
        );
        let signer = tsa_under(&intermediate.certificate, &intermediate.key);
        let anchors = [authority.root_certificate.clone()];
        let companions = [intermediate.certificate.clone()];
        let crls = [
            crl_by(&intermediate.certificate, &intermediate.key),
            crl_by(&authority.root_certificate, &authority.root_key),
        ];
        let verdict = validate_chain(
            &signer,
            &TrustPool {
                anchors: &anchors,
                companions: &companions,
                crls: &crls,
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(verdict, Ok(()));
    }

    #[test]
    fn an_intermediate_without_the_ca_flag_is_refused() {
        let authority = test_pki::standard_authority();
        let intermediate = intermediate_under(
            &authority.root_certificate,
            &authority.root_key,
            // Key usage alone does not make an authority; the CA flag
            // is missing.
            vec![test_pki::extension_of(
                &KeyUsage(
                    x509_cert::ext::pkix::KeyUsages::KeyCertSign
                        | x509_cert::ext::pkix::KeyUsages::CRLSign,
                ),
                true,
            )],
        );
        let signer = tsa_under(&intermediate.certificate, &intermediate.key);
        let anchors = [authority.root_certificate.clone()];
        let companions = [intermediate.certificate.clone()];
        let verdict = validate_chain(
            &signer,
            &TrustPool {
                anchors: &anchors,
                companions: &companions,
                crls: &[],
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(
            verdict,
            Err(Error::IssuerNotAuthority {
                issuer: "CN=Tydence Test Mid".to_string(),
            })
        );
    }

    #[test]
    fn a_zero_path_length_forbids_a_second_intermediate() {
        let authority = test_pki::standard_authority();
        let near_root = intermediate_under(
            &authority.root_certificate,
            &authority.root_key,
            vec![
                test_pki::extension_of(
                    &BasicConstraints {
                        ca: true,
                        path_len_constraint: Some(0),
                    },
                    true,
                ),
                test_pki::extension_of(
                    &KeyUsage(
                        x509_cert::ext::pkix::KeyUsages::KeyCertSign
                            | x509_cert::ext::pkix::KeyUsages::CRLSign,
                    ),
                    true,
                ),
            ],
        );
        let second_key = test_pki::signing_key_from_seed(0x66);
        let second = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 7,
                issuer: near_root.certificate.tbs_certificate.subject.clone(),
                subject: test_pki::parse_name("CN=Tydence Test Deep Mid"),
                key_info: test_pki::key_info_of(&second_key),
                validity: test_pki::standard_validity(),
                extensions: test_pki::ca_extensions(),
            },
            &near_root.key,
        );
        let signer = tsa_under(&second, &second_key);
        let anchors = [authority.root_certificate.clone()];
        let companions = [near_root.certificate.clone(), second.clone()];
        let crls = [
            crl_by(&second, &second_key),
            crl_by(&near_root.certificate, &near_root.key),
            crl_by(&authority.root_certificate, &authority.root_key),
        ];
        let verdict = validate_chain(
            &signer,
            &TrustPool {
                anchors: &anchors,
                companions: &companions,
                crls: &crls,
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(
            verdict,
            Err(Error::PathLengthExceeded {
                issuer: "CN=Tydence Test Mid".to_string(),
            })
        );
    }

    #[test]
    fn a_signer_without_any_issuer_is_untrusted() {
        let authority = test_pki::standard_authority();
        let verdict = validate_chain(
            &authority.tsa_certificate,
            &TrustPool {
                anchors: &[],
                companions: &[],
                crls: &[],
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(
            verdict,
            Err(Error::NoTrustedIssuer {
                subject: "CN=Tydence Test TSA".to_string(),
            })
        );
    }

    #[test]
    fn a_certificate_outside_its_validity_fails() {
        let authority = test_pki::authority_with_tsa_blueprint(|blueprint| {
            blueprint.validity = test_pki::validity_between(
                test_pki::GEN_TIME_UNIX_SECONDS + test_pki::DAY_SECONDS,
                test_pki::GEN_TIME_UNIX_SECONDS + 2 * test_pki::DAY_SECONDS,
            );
        });
        let anchors = [authority.root_certificate.clone()];
        let verdict = validate_chain(
            &authority.tsa_certificate,
            &TrustPool {
                anchors: &anchors,
                companions: &[],
                crls: &[],
            },
            test_pki::gen_time_moment(),
        );
        assert!(matches!(verdict, Err(Error::OutsideValidity { .. })));
    }

    #[test]
    fn an_unknown_critical_extension_fails_closed() {
        let authority = test_pki::authority_with_tsa_blueprint(|blueprint| {
            blueprint.extensions.push(test_pki::extension_of(
                &SubjectKeyIdentifier(
                    der::asn1::OctetString::new(vec![1, 2, 3])
                        .expect("short octet strings encode"),
                ),
                true,
            ));
        });
        let anchors = [authority.root_certificate.clone()];
        let crls = [test_pki::standard_crl(&authority)];
        let verdict = validate_chain(
            &authority.tsa_certificate,
            &TrustPool {
                anchors: &anchors,
                companions: &[],
                crls: &crls,
            },
            test_pki::gen_time_moment(),
        );
        assert!(matches!(
            verdict,
            Err(Error::UnknownCriticalExtension { .. })
        ));
    }

    #[test]
    fn a_cross_signing_cycle_ends_as_too_long() {
        let first_key = test_pki::signing_key_from_seed(0x21);
        let second_key = test_pki::signing_key_from_seed(0x31);
        let first = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 8,
                issuer: test_pki::parse_name("CN=Cycle B"),
                subject: test_pki::parse_name("CN=Cycle A"),
                key_info: test_pki::key_info_of(&first_key),
                validity: test_pki::standard_validity(),
                extensions: test_pki::ca_extensions(),
            },
            &second_key,
        );
        let second = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 9,
                issuer: test_pki::parse_name("CN=Cycle A"),
                subject: test_pki::parse_name("CN=Cycle B"),
                key_info: test_pki::key_info_of(&second_key),
                validity: test_pki::standard_validity(),
                extensions: test_pki::ca_extensions(),
            },
            &first_key,
        );
        let companions = [first.clone(), second.clone()];
        let crls = [crl_by(&first, &first_key), crl_by(&second, &second_key)];
        let verdict = validate_chain(
            &first,
            &TrustPool {
                anchors: &[],
                companions: &companions,
                crls: &crls,
            },
            test_pki::gen_time_moment(),
        );
        assert_eq!(verdict, Err(Error::ChainTooLong));
    }
}
