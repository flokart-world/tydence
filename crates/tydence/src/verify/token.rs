//! Full token verification (stamping specification §7 check 3).
//!
//! A token is accepted only when every question about it has a
//! positive answer: the imprint reproduces from the manifest bytes,
//! the CMS signature verifies over the signed attributes, the signer
//! certificate is the one the ESS attribute binds (RFC 5816: both
//! ESSCertID generations must be supported), the chain reaches a
//! caller-supplied trust anchor, the certificate was fit for
//! timestamping, and the sealed CRL snapshots clear it at genTime.
//! The verifier has no clock: genTime is the only moment anything is
//! judged at.

use cms::cert::CertificateChoices;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Any, Decode, Encode};
use sha1::{Digest, Sha1};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::attr::Attributes;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_tsp::{TspVersion, TstInfo};

use super::ess::{IssuerSerial, SigningCertificate, SigningCertificateV2};
use super::oids::{
    ID_AA_SIGNING_CERTIFICATE, ID_AA_SIGNING_CERTIFICATE_V2, ID_CONTENT_TYPE,
    ID_CT_TST_INFO, ID_KP_TIME_STAMPING, ID_MESSAGE_DIGEST, ID_SHA_1,
    ID_SHA_256, ID_SIGNED_DATA,
};
use super::path::{self, TrustPool};
use super::tsp::{ImprintAlgorithm, is_absent_or_null_parameter};
use super::x509::{
    FailureCause, NormalizeError, RawSignature, SignatureError,
    decode_extension, normalize_cms_signature_algorithm,
    verify_issued_signature,
};

#[derive(Debug)]
pub enum Error {
    /// The token bytes do not parse as the structure they claim to
    /// be.
    Malformed {
        source: FailureCause,
    },
    NotSignedData {
        content_type: String,
    },
    NotTstInfo {
        econtent_type: String,
    },
    /// The signed content is detached; a token must carry its
    /// TSTInfo.
    MissingContent,
    UnsupportedTstVersion,
    /// The TSTInfo carries extensions this implementation cannot
    /// judge.
    UnexpectedExtensions,
    UnsupportedImprintAlgorithm {
        oid: ObjectIdentifier,
    },
    /// The token's message imprint is not a digest of the manifest
    /// bytes.
    ImprintMismatch,
    WrongSignerCount {
        count: usize,
    },
    MissingCertificates,
    /// No embedded certificate matches the signer identifier.
    SignerCertificateNotFound,
    /// Several embedded certificates match the signer identifier.
    AmbiguousSignerCertificate,
    /// The SignerInfo version contradicts its identifier form
    /// (RFC 5652 §5.3).
    InconsistentSignerVersion,
    /// RFC 3161 §2.4.2 requires signed attributes; a bare signature
    /// over the content is not a valid token.
    MissingSignedAttributes,
    /// The attribute is duplicated, empty, multi-valued, or its
    /// value does not decode.
    MalformedAttribute {
        oid: ObjectIdentifier,
    },
    /// The content-type attribute does not name TSTInfo.
    ContentTypeMismatch,
    /// The message-digest attribute does not match the signed
    /// content.
    MessageDigestMismatch,
    UnsupportedDigestAlgorithm {
        oid: ObjectIdentifier,
    },
    /// Neither ESS signing-certificate attribute is present, so the
    /// token does not bind its signer certificate (RFC 3161 §2.4.2).
    MissingSigningCertificateAttribute,
    /// An ESS attribute is present but does not identify the signer
    /// certificate actually used.
    SigningCertificateMismatch,
    UnsupportedCertificateHash {
        oid: ObjectIdentifier,
    },
    UnsupportedSignature(NormalizeError),
    InvalidSignature,
    /// The trust material (anchor or companion certificates, CRLs)
    /// does not parse; nothing can be decided against it.
    MalformedTrustInput {
        source: FailureCause,
    },
    /// Without a trust anchor no chain can mean anything.
    NoTrustAnchors,
    UntrustedChain(path::Error),
    /// The signer certificate's extended key usage is not the
    /// critical, exclusive id-kp-timeStamping RFC 3161 §2.3 demands.
    UnfitExtendedKeyUsage,
    /// The signer certificate's key usage rules out signing.
    ForbiddenKeyUsage,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { .. } => {
                write!(formatter, "the token fails to parse")
            }
            Self::NotSignedData { content_type } => write!(
                formatter,
                "the token is not a CMS SignedData \
                 (content type {content_type})"
            ),
            Self::NotTstInfo { econtent_type } => write!(
                formatter,
                "the token's signed content is not a TSTInfo \
                 (content type {econtent_type})"
            ),
            Self::MissingContent => {
                write!(formatter, "the token's signed content is detached")
            }
            Self::UnsupportedTstVersion => {
                write!(formatter, "the TSTInfo version is not 1")
            }
            Self::UnexpectedExtensions => write!(
                formatter,
                "the TSTInfo carries extensions this verifier cannot judge"
            ),
            Self::UnsupportedImprintAlgorithm { oid } => write!(
                formatter,
                "message imprint algorithm {oid} is unsupported"
            ),
            Self::ImprintMismatch => write!(
                formatter,
                "the message imprint is not a digest of the manifest bytes"
            ),
            Self::WrongSignerCount { count } => write!(
                formatter,
                "the token carries {count} signer infos where RFC 3161 \
                 requires exactly one"
            ),
            Self::MissingCertificates => write!(
                formatter,
                "the token embeds no certificates to verify against"
            ),
            Self::SignerCertificateNotFound => write!(
                formatter,
                "no embedded certificate matches the signer identifier"
            ),
            Self::AmbiguousSignerCertificate => write!(
                formatter,
                "several embedded certificates match the signer identifier"
            ),
            Self::InconsistentSignerVersion => write!(
                formatter,
                "the SignerInfo version contradicts its identifier form"
            ),
            Self::MissingSignedAttributes => {
                write!(formatter, "the token carries no signed attributes")
            }
            Self::MalformedAttribute { oid } => write!(
                formatter,
                "signed attribute {oid} is missing, duplicated or malformed"
            ),
            Self::ContentTypeMismatch => write!(
                formatter,
                "the content-type attribute does not name TSTInfo"
            ),
            Self::MessageDigestMismatch => write!(
                formatter,
                "the message-digest attribute does not match the signed \
                 content"
            ),
            Self::UnsupportedDigestAlgorithm { oid } => {
                write!(formatter, "digest algorithm {oid} is unsupported")
            }
            Self::MissingSigningCertificateAttribute => write!(
                formatter,
                "the token carries no ESS signing-certificate attribute"
            ),
            Self::SigningCertificateMismatch => write!(
                formatter,
                "the ESS attribute does not identify the signer certificate"
            ),
            Self::UnsupportedCertificateHash { oid } => write!(
                formatter,
                "certificate hash algorithm {oid} is unsupported"
            ),
            Self::UnsupportedSignature(cause) => {
                write!(formatter, "unsupported signature: {cause}")
            }
            Self::InvalidSignature => {
                write!(formatter, "the CMS signature does not verify")
            }
            Self::MalformedTrustInput { .. } => {
                write!(formatter, "the supplied trust material fails to parse")
            }
            Self::NoTrustAnchors => {
                write!(formatter, "no trust anchors were supplied")
            }
            Self::UntrustedChain(cause) => {
                write!(formatter, "the certificate chain fails: {cause}")
            }
            Self::UnfitExtendedKeyUsage => write!(
                formatter,
                "the signer certificate's extended key usage is not the \
                 critical, exclusive id-kp-timeStamping"
            ),
            Self::ForbiddenKeyUsage => write!(
                formatter,
                "the signer certificate's key usage rules out signing"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed { source }
            | Self::MalformedTrustInput { source } => Some(source.as_ref()),
            Self::UnsupportedSignature(cause) => Some(cause),
            Self::UntrustedChain(cause) => Some(cause),
            _ => None,
        }
    }
}

/// The trust material a token is judged against, DER-encoded. The
/// anchors are what the caller trusts axiomatically; the companions
/// are additional intermediate certificates (from `ltv/`) beyond the
/// ones the token embeds; the CRLs are the sealed historical
/// snapshots.
#[derive(Clone, Copy, Debug)]
pub struct TrustData<'a> {
    pub anchor_certificates: &'a [Vec<u8>],
    pub companion_certificates: &'a [Vec<u8>],
    pub crls: &'a [Vec<u8>],
}

/// What the verifier holds independently of any token: the exact
/// manifest bytes a token must cover, and the trust material it is
/// judged against. Bundling them keeps [`verify_token`] from taking
/// two adjacent byte slices a call site could silently transpose.
#[derive(Clone, Copy, Debug)]
pub struct VerificationBasis<'a> {
    /// The exact bytes of `.tydence/manifest`.
    pub manifest_bytes: &'a [u8],
    pub trust: TrustData<'a>,
}

/// What a verified token established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenSummary {
    /// The TSA-asserted moment the imprint existed.
    pub gen_time: SystemTime,
    pub imprint_algorithm: ImprintAlgorithm,
}

fn malformed(source: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Malformed {
        source: Box::new(source),
    }
}

/// Maps a digest AlgorithmIdentifier to the SHA-2 family it names,
/// applying the absent-or-NULL parameter reading of RFC 5754.
fn digest_family_of(
    identifier: &AlgorithmIdentifierOwned,
) -> Option<ImprintAlgorithm> {
    if !is_absent_or_null_parameter(&identifier.parameters) {
        return None;
    }
    ImprintAlgorithm::from_digest_oid(identifier.oid)
}

fn decode_signed_data(token_bytes: &[u8]) -> Result<SignedData, Error> {
    let content_info =
        ContentInfo::from_der(token_bytes).map_err(malformed)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::NotSignedData {
            content_type: content_info.content_type.to_string(),
        });
    }
    content_info
        .content
        .decode_as::<SignedData>()
        .map_err(malformed)
}

/// Returns the TSTInfo together with the exact content bytes the
/// message-digest attribute covers.
fn decode_tst_info(signed: &SignedData) -> Result<(TstInfo, Vec<u8>), Error> {
    let encapsulated = &signed.encap_content_info;
    if encapsulated.econtent_type != ID_CT_TST_INFO {
        return Err(Error::NotTstInfo {
            econtent_type: encapsulated.econtent_type.to_string(),
        });
    }
    let econtent = encapsulated
        .econtent
        .as_ref()
        .ok_or(Error::MissingContent)?;
    let content_octets =
        econtent.decode_as::<OctetString>().map_err(malformed)?;
    let tst_info =
        TstInfo::from_der(content_octets.as_bytes()).map_err(malformed)?;
    Ok((tst_info, content_octets.as_bytes().to_vec()))
}

fn ensure_imprint_matches(
    tst_info: &TstInfo,
    manifest_bytes: &[u8],
) -> Result<ImprintAlgorithm, Error> {
    let imprint = &tst_info.message_imprint;
    let family =
        digest_family_of(&imprint.hash_algorithm).ok_or_else(|| {
            Error::UnsupportedImprintAlgorithm {
                oid: imprint.hash_algorithm.oid,
            }
        })?;
    if imprint.hashed_message.as_bytes()
        == family.digest_payload(manifest_bytes)
    {
        Ok(family)
    } else {
        Err(Error::ImprintMismatch)
    }
}

fn single_signer(signed: &SignedData) -> Result<&SignerInfo, Error> {
    let signers = signed.signer_infos.0.as_slice();
    match signers {
        [signer_info] => Ok(signer_info),
        _ => Err(Error::WrongSignerCount {
            count: signers.len(),
        }),
    }
}

fn collect_certificates(
    signed: &SignedData,
) -> Result<Vec<&Certificate>, Error> {
    let choices = signed
        .certificates
        .as_ref()
        .ok_or(Error::MissingCertificates)?;
    // Non-certificate choices carry nothing a chain can use; they
    // are dropped rather than refused because they can only shrink
    // the pool trust is built from.
    let certificates: Vec<&Certificate> = choices
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    if certificates.is_empty() {
        return Err(Error::MissingCertificates);
    }
    Ok(certificates)
}

fn matches_signer_identifier(
    sid: &SignerIdentifier,
    certificate: &Certificate,
) -> Result<bool, Error> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => Ok(
            issuer_and_serial.issuer == certificate.tbs_certificate.issuer
                && issuer_and_serial.serial_number
                    == certificate.tbs_certificate.serial_number,
        ),
        SignerIdentifier::SubjectKeyIdentifier(key_identifier) => {
            let subject_key = decode_extension::<SubjectKeyIdentifier>(
                certificate.tbs_certificate.extensions.as_ref(),
            )
            .map_err(malformed)?;
            Ok(subject_key
                .is_some_and(|decoded| decoded.value == *key_identifier))
        }
    }
}

fn find_signer_certificate<'a>(
    signer_info: &SignerInfo,
    certificates: &[&'a Certificate],
) -> Result<&'a Certificate, Error> {
    let expected_version = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
        SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
    };
    if signer_info.version != expected_version {
        return Err(Error::InconsistentSignerVersion);
    }
    let mut matches = Vec::new();
    for certificate in certificates {
        if matches_signer_identifier(&signer_info.sid, certificate)? {
            matches.push(*certificate);
        }
    }
    match matches.as_slice() {
        [] => Err(Error::SignerCertificateNotFound),
        [signer_certificate] => Ok(signer_certificate),
        _ => Err(Error::AmbiguousSignerCertificate),
    }
}

/// Returns the single value of the attribute, `None` when the
/// attribute is absent, and an error when it is duplicated or not
/// single-valued (RFC 5652 §11 defines all of these as single-valued
/// and unrepeatable).
fn unique_attribute_value(
    attributes: &Attributes,
    oid: ObjectIdentifier,
) -> Result<Option<&Any>, Error> {
    let mut instances =
        attributes.iter().filter(|attribute| attribute.oid == oid);
    let Some(attribute) = instances.next() else {
        return Ok(None);
    };
    if instances.next().is_some() {
        return Err(Error::MalformedAttribute { oid });
    }
    match attribute.values.as_slice() {
        [value] => Ok(Some(value)),
        _ => Err(Error::MalformedAttribute { oid }),
    }
}

fn ensure_content_type_attribute(
    attributes: &Attributes,
) -> Result<(), Error> {
    let value = unique_attribute_value(attributes, ID_CONTENT_TYPE)?.ok_or(
        Error::MalformedAttribute {
            oid: ID_CONTENT_TYPE,
        },
    )?;
    let named_type = value.decode_as::<ObjectIdentifier>().map_err(|_| {
        Error::MalformedAttribute {
            oid: ID_CONTENT_TYPE,
        }
    })?;
    if named_type == ID_CT_TST_INFO {
        Ok(())
    } else {
        Err(Error::ContentTypeMismatch)
    }
}

fn ensure_message_digest_attribute(
    attributes: &Attributes,
    digest_family: ImprintAlgorithm,
    content_bytes: &[u8],
) -> Result<(), Error> {
    let value = unique_attribute_value(attributes, ID_MESSAGE_DIGEST)?.ok_or(
        Error::MalformedAttribute {
            oid: ID_MESSAGE_DIGEST,
        },
    )?;
    let declared_digest = value.decode_as::<OctetString>().map_err(|_| {
        Error::MalformedAttribute {
            oid: ID_MESSAGE_DIGEST,
        }
    })?;
    if declared_digest.as_bytes()
        == digest_family.digest_payload(content_bytes)
    {
        Ok(())
    } else {
        Err(Error::MessageDigestMismatch)
    }
}

fn matches_issuer_serial(
    issuer_serial: &IssuerSerial,
    signer_certificate: &Certificate,
) -> bool {
    // RFC 5035 §4: the GeneralNames must carry exactly the issuer's
    // directory name. Any other shape fails closed.
    let names_issuer = match issuer_serial.issuer.as_slice() {
        [GeneralName::DirectoryName(name)] => {
            *name == signer_certificate.tbs_certificate.issuer
        }
        _ => false,
    };
    names_issuer
        && issuer_serial.serial_number
            == signer_certificate.tbs_certificate.serial_number
}

/// Judges one ESS certificate identification against the signer
/// certificate's DER.
struct EssIdentification<'a> {
    hash_oid: ObjectIdentifier,
    cert_hash: &'a [u8],
    issuer_serial: Option<&'a IssuerSerial>,
}

fn ensure_identifies_signer(
    identification: &EssIdentification<'_>,
    signer_der: &[u8],
    signer_certificate: &Certificate,
) -> Result<(), Error> {
    let expected = match identification.hash_oid {
        ID_SHA_1 => Sha1::digest(signer_der).to_vec(),
        supported => ImprintAlgorithm::from_digest_oid(supported)
            .ok_or(Error::UnsupportedCertificateHash { oid: supported })?
            .digest_payload(signer_der),
    };
    if identification.cert_hash != expected {
        return Err(Error::SigningCertificateMismatch);
    }
    let issuer_serial_agrees =
        identification.issuer_serial.is_none_or(|issuer_serial| {
            matches_issuer_serial(issuer_serial, signer_certificate)
        });
    if issuer_serial_agrees {
        Ok(())
    } else {
        Err(Error::SigningCertificateMismatch)
    }
}

fn ensure_signing_certificate_attribute(
    attributes: &Attributes,
    signer_certificate: &Certificate,
) -> Result<(), Error> {
    let signer_der = signer_certificate.to_der().map_err(malformed)?;
    let mut bound = false;
    if let Some(value) =
        unique_attribute_value(attributes, ID_AA_SIGNING_CERTIFICATE)?
    {
        let attribute =
            value.decode_as::<SigningCertificate>().map_err(|_| {
                Error::MalformedAttribute {
                    oid: ID_AA_SIGNING_CERTIFICATE,
                }
            })?;
        // RFC 2634 §5.4: the first entry names the signer itself;
        // later entries may describe the chain and are not judged.
        let first =
            attribute.certs.first().ok_or(Error::MalformedAttribute {
                oid: ID_AA_SIGNING_CERTIFICATE,
            })?;
        ensure_identifies_signer(
            &EssIdentification {
                hash_oid: ID_SHA_1,
                cert_hash: first.cert_hash.as_bytes(),
                issuer_serial: first.issuer_serial.as_ref(),
            },
            &signer_der,
            signer_certificate,
        )?;
        bound = true;
    }
    if let Some(value) =
        unique_attribute_value(attributes, ID_AA_SIGNING_CERTIFICATE_V2)?
    {
        let attribute =
            value.decode_as::<SigningCertificateV2>().map_err(|_| {
                Error::MalformedAttribute {
                    oid: ID_AA_SIGNING_CERTIFICATE_V2,
                }
            })?;
        let first =
            attribute.certs.first().ok_or(Error::MalformedAttribute {
                oid: ID_AA_SIGNING_CERTIFICATE_V2,
            })?;
        let hash_oid = match &first.hash_algorithm {
            // RFC 5035 §4: an absent algorithm means SHA-256
            None => ID_SHA_256,
            Some(declared) => {
                if !is_absent_or_null_parameter(&declared.parameters) {
                    return Err(Error::UnsupportedCertificateHash {
                        oid: declared.oid,
                    });
                }
                declared.oid
            }
        };
        ensure_identifies_signer(
            &EssIdentification {
                hash_oid,
                cert_hash: first.cert_hash.as_bytes(),
                issuer_serial: first.issuer_serial.as_ref(),
            },
            &signer_der,
            signer_certificate,
        )?;
        bound = true;
    }
    if bound {
        Ok(())
    } else {
        Err(Error::MissingSigningCertificateAttribute)
    }
}

fn verify_cms_signature(
    signer_info: &SignerInfo,
    attributes: &Attributes,
    signer_certificate: &Certificate,
) -> Result<(), Error> {
    // RFC 5652 §5.4: with signed attributes present, the signature
    // covers their DER encoding under the plain SET OF tag.
    let message = attributes.to_der().map_err(malformed)?;
    let algorithm = normalize_cms_signature_algorithm(
        signer_info.digest_alg.oid,
        &signer_info.signature_algorithm,
    )
    .map_err(Error::UnsupportedSignature)?;
    let verdict = verify_issued_signature(
        &message,
        &RawSignature {
            algorithm: &algorithm,
            bytes: signer_info.signature.as_bytes(),
        },
        signer_certificate,
    );
    match verdict {
        Ok(()) => Ok(()),
        Err(SignatureError::Unsupported { oid }) => {
            Err(Error::UnsupportedSignature(
                NormalizeError::UnsupportedSignatureAlgorithm { oid },
            ))
        }
        Err(_) => Err(Error::InvalidSignature),
    }
}

fn ensure_time_stamping_usage(
    signer_certificate: &Certificate,
) -> Result<(), Error> {
    let extensions = signer_certificate.tbs_certificate.extensions.as_ref();
    let extended_key_usage = decode_extension::<ExtendedKeyUsage>(extensions)
        .map_err(|_| Error::UnfitExtendedKeyUsage)?
        .ok_or(Error::UnfitExtendedKeyUsage)?;
    // RFC 3161 §2.3: the extension must be critical and must contain
    // only id-kp-timeStamping — the key is dedicated to timestamping,
    // so no compromise of a general-purpose key can mint tokens.
    let dedicated_to_time_stamping = extended_key_usage.critical
        && extended_key_usage.value.0.as_slice() == [ID_KP_TIME_STAMPING];
    if !dedicated_to_time_stamping {
        return Err(Error::UnfitExtendedKeyUsage);
    }
    // RFC 3161 says nothing about key usage bits; this is RFC 5280
    // §4.2.1.3 discipline. digitalSignature and nonRepudiation are
    // the two bits that authorize signing ordinary content, so a key
    // usage extension granting neither disavows the very operation
    // the token rests on. An absent extension restricts nothing.
    let key_usage = decode_extension::<KeyUsage>(extensions)
        .map_err(|_| Error::ForbiddenKeyUsage)?;
    let grants_content_signing = key_usage
        .map(|decoded| {
            decoded.value.digital_signature()
                || decoded.value.non_repudiation()
        })
        .unwrap_or(true);
    if grants_content_signing {
        Ok(())
    } else {
        Err(Error::ForbiddenKeyUsage)
    }
}

fn parse_certificate_list(
    der_list: &[Vec<u8>],
) -> Result<Vec<Certificate>, Error> {
    der_list
        .iter()
        .map(|der_bytes| {
            Certificate::from_der(der_bytes).map_err(|source| {
                Error::MalformedTrustInput {
                    source: Box::new(source),
                }
            })
        })
        .collect()
}

fn parse_crl_list(
    der_list: &[Vec<u8>],
) -> Result<Vec<CertificateList>, Error> {
    der_list
        .iter()
        .map(|der_bytes| {
            CertificateList::from_der(der_bytes).map_err(|source| {
                Error::MalformedTrustInput {
                    source: Box::new(source),
                }
            })
        })
        .collect()
}

/// Verifies one raw token (DER) against the verification basis —
/// the manifest bytes it claims to cover and the supplied trust
/// material (stamping specification §7 check 3). Fail-closed
/// throughout: anything undecidable refuses the token.
pub fn verify_token(
    token_bytes: &[u8],
    basis: &VerificationBasis<'_>,
) -> Result<TokenSummary, Error> {
    let signed = decode_signed_data(token_bytes)?;
    let (tst_info, content_bytes) = decode_tst_info(&signed)?;
    if tst_info.version != TspVersion::V1 {
        return Err(Error::UnsupportedTstVersion);
    }
    if tst_info.extensions.is_some() {
        return Err(Error::UnexpectedExtensions);
    }
    let imprint_algorithm =
        ensure_imprint_matches(&tst_info, basis.manifest_bytes)?;
    let signer_info = single_signer(&signed)?;
    let embedded_certificates = collect_certificates(&signed)?;
    let signer_certificate =
        find_signer_certificate(signer_info, &embedded_certificates)?;
    let attributes = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(Error::MissingSignedAttributes)?;
    let digest_family = digest_family_of(&signer_info.digest_alg).ok_or(
        Error::UnsupportedDigestAlgorithm {
            oid: signer_info.digest_alg.oid,
        },
    )?;
    ensure_content_type_attribute(attributes)?;
    ensure_message_digest_attribute(
        attributes,
        digest_family,
        &content_bytes,
    )?;
    ensure_signing_certificate_attribute(attributes, signer_certificate)?;
    verify_cms_signature(signer_info, attributes, signer_certificate)?;
    if basis.trust.anchor_certificates.is_empty() {
        return Err(Error::NoTrustAnchors);
    }
    let anchors = parse_certificate_list(basis.trust.anchor_certificates)?;
    let extra_companions =
        parse_certificate_list(basis.trust.companion_certificates)?;
    let crls = parse_crl_list(basis.trust.crls)?;
    let mut companions: Vec<Certificate> = embedded_certificates
        .iter()
        .map(|certificate| (*certificate).clone())
        .collect();
    companions.extend(extra_companions);
    let gen_time = UNIX_EPOCH + tst_info.gen_time.to_unix_duration();
    path::validate_chain(
        signer_certificate,
        &TrustPool {
            anchors: &anchors,
            companions: &companions,
            crls: &crls,
        },
        gen_time,
    )
    .map_err(Error::UntrustedChain)?;
    ensure_time_stamping_usage(signer_certificate)?;
    Ok(TokenSummary {
        gen_time,
        imprint_algorithm,
    })
}

#[cfg(test)]
use super::{ess, oids, revocation, test_pki, transport};

#[cfg(test)]
mod tests {
    use der::asn1::SetOfVec;
    use std::fs;
    use std::path::{Path, PathBuf};
    use x509_cert::attr::Attribute;
    use x509_cert::ext::pkix::KeyUsages;
    use x509_tsp::TimeStampResp;

    use super::ess::EssCertIdV2;
    use super::oids::ID_ECDSA_WITH_SHA_512;

    use super::*;

    const MANIFEST_BYTES: &[u8] = b"tydence-manifest/v1\n";

    fn basis_of<'a>(
        bundle: &'a test_pki::TrustDers,
        manifest_bytes: &'a [u8],
    ) -> VerificationBasis<'a> {
        VerificationBasis {
            manifest_bytes,
            trust: TrustData {
                anchor_certificates: &bundle.anchors,
                companion_certificates: &bundle.companions,
                crls: &bundle.crls,
            },
        }
    }

    fn verify_against(
        parts: &test_pki::TokenParts,
        authority: &test_pki::Authority,
    ) -> Result<TokenSummary, Error> {
        let bundle = test_pki::standard_trust_ders(authority);
        verify_token(
            &test_pki::encode_token(parts, &authority.tsa_key),
            &basis_of(&bundle, MANIFEST_BYTES),
        )
    }

    fn attributes_without(
        attributes: &SetOfVec<Attribute>,
        oid: ObjectIdentifier,
    ) -> SetOfVec<Attribute> {
        let mut remaining = SetOfVec::new();
        for attribute in attributes.iter() {
            if attribute.oid != oid {
                remaining
                    .insert(attribute.clone())
                    .expect("distinct attributes insert");
            }
        }
        remaining
    }

    fn replace_attribute(
        attributes: &SetOfVec<Attribute>,
        replacement: Attribute,
    ) -> SetOfVec<Attribute> {
        let mut replaced = attributes_without(attributes, replacement.oid);
        replaced
            .insert(replacement)
            .expect("distinct attributes insert");
        replaced
    }

    fn v2_attribute_with_issuer_serial(
        signer_certificate: &Certificate,
        serial_byte: u8,
    ) -> Attribute {
        use sha2::{Digest, Sha256};
        let identification = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None,
                cert_hash: OctetString::new(
                    Sha256::digest(test_pki::der_of(signer_certificate))
                        .to_vec(),
                )
                .expect("digests encode"),
                issuer_serial: Some(IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(
                        signer_certificate.tbs_certificate.issuer.clone(),
                    )],
                    serial_number:
                        x509_cert::serial_number::SerialNumber::new(&[
                            serial_byte,
                        ])
                        .expect("single-byte serials encode"),
                }),
            }],
            policies: None,
        };
        test_pki::attribute_of(ID_AA_SIGNING_CERTIFICATE_V2, &identification)
    }

    #[test]
    fn a_standard_token_verifies_end_to_end() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let summary = verify_against(&parts, &authority)
            .expect("the standard token verifies");
        assert_eq!(
            summary,
            TokenSummary {
                gen_time: test_pki::gen_time_moment(),
                imprint_algorithm: ImprintAlgorithm::Sha256,
            }
        );
    }

    #[test]
    fn a_v1_ess_attribute_also_binds_the_signer() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &attributes_without(
                &parts.attributes,
                ID_AA_SIGNING_CERTIFICATE_V2,
            ),
            test_pki::signing_certificate_v1_attribute(
                &authority.tsa_certificate,
            ),
        );
        assert!(verify_against(&parts, &authority).is_ok());
    }

    #[test]
    fn both_ess_generations_may_bind_together() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            test_pki::signing_certificate_v1_attribute(
                &authority.tsa_certificate,
            ),
        );
        assert!(verify_against(&parts, &authority).is_ok());
    }

    #[test]
    fn a_different_manifest_fails_the_imprint() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let bundle = test_pki::standard_trust_ders(&authority);
        let verdict = verify_token(
            &test_pki::encode_token(&parts, &authority.tsa_key),
            &basis_of(&bundle, b"tydence-manifest/v1\nparents -- beef\n"),
        );
        assert!(matches!(verdict, Err(Error::ImprintMismatch)));
    }

    #[test]
    fn tst_info_extensions_fail_closed() {
        let authority = test_pki::standard_authority();
        let mut tst_info = test_pki::standard_tst_info(MANIFEST_BYTES);
        tst_info.extensions = Some(vec![]);
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.content_bytes = test_pki::der_of(&tst_info);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnexpectedExtensions)
        ));
    }

    #[test]
    fn an_unsupported_imprint_algorithm_fails() {
        let authority = test_pki::standard_authority();
        let mut tst_info = test_pki::standard_tst_info(MANIFEST_BYTES);
        tst_info.message_imprint.hash_algorithm.oid = ID_SHA_1;
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.content_bytes = test_pki::der_of(&tst_info);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnsupportedImprintAlgorithm { .. })
        ));
    }

    #[test]
    fn a_tampered_message_digest_fails() {
        use sha2::{Digest, Sha256};
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            test_pki::attribute_of(
                ID_MESSAGE_DIGEST,
                &OctetString::new(Sha256::digest(b"other bytes").to_vec())
                    .expect("digests encode"),
            ),
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::MessageDigestMismatch)
        ));
    }

    #[test]
    fn a_missing_content_type_attribute_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes =
            attributes_without(&parts.attributes, ID_CONTENT_TYPE);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::MalformedAttribute {
                oid: ID_CONTENT_TYPE,
            })
        ));
    }

    #[test]
    fn a_wrong_content_type_attribute_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            test_pki::attribute_of(ID_CONTENT_TYPE, &ID_SIGNED_DATA),
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::ContentTypeMismatch)
        ));
    }

    #[test]
    fn missing_signed_attributes_fail_closed() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.omit_signed_attributes = true;
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::MissingSignedAttributes)
        ));
    }

    #[test]
    fn a_tampered_signature_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.signature_override = Some(test_pki::sign_der_message(
            &authority.tsa_key,
            b"a different message entirely",
        ));
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn a_missing_ess_attribute_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = attributes_without(
            &parts.attributes,
            ID_AA_SIGNING_CERTIFICATE_V2,
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::MissingSigningCertificateAttribute)
        ));
    }

    #[test]
    fn an_ess_hash_of_another_certificate_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            test_pki::signing_certificate_v2_attribute(
                &authority.root_certificate,
            ),
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::SigningCertificateMismatch)
        ));
    }

    #[test]
    fn a_matching_issuer_serial_is_accepted() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            v2_attribute_with_issuer_serial(&authority.tsa_certificate, 2),
        );
        assert!(verify_against(&parts, &authority).is_ok());
    }

    #[test]
    fn a_disagreeing_issuer_serial_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.attributes = replace_attribute(
            &parts.attributes,
            v2_attribute_with_issuer_serial(&authority.tsa_certificate, 9),
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::SigningCertificateMismatch)
        ));
    }

    #[test]
    fn a_token_without_certificates_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.certificates = vec![];
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::MissingCertificates)
        ));
    }

    #[test]
    fn an_unknown_signer_identifier_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.sid = SignerIdentifier::IssuerAndSerialNumber(
            cms::cert::IssuerAndSerialNumber {
                issuer: authority
                    .tsa_certificate
                    .tbs_certificate
                    .issuer
                    .clone(),
                serial_number: x509_cert::serial_number::SerialNumber::new(&[
                    9,
                ])
                .expect("single-byte serials encode"),
            },
        );
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::SignerCertificateNotFound)
        ));
    }

    #[test]
    fn an_inconsistent_signer_version_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.signer_version = CmsVersion::V3;
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::InconsistentSignerVersion)
        ));
    }

    #[test]
    fn an_unsupported_digest_algorithm_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.digest_algorithm = AlgorithmIdentifierOwned {
            oid: ID_SHA_1,
            parameters: None,
        };
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnsupportedDigestAlgorithm { .. })
        ));
    }

    #[test]
    fn a_contradictory_signature_algorithm_fails() {
        let authority = test_pki::standard_authority();
        let mut parts =
            test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        parts.signature_algorithm = AlgorithmIdentifierOwned {
            oid: ID_ECDSA_WITH_SHA_512,
            parameters: None,
        };
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnsupportedSignature(
                NormalizeError::DigestSignatureMismatch { .. }
            ))
        ));
    }

    #[test]
    fn an_empty_anchor_set_fails() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let mut bundle = test_pki::standard_trust_ders(&authority);
        bundle.anchors = vec![];
        let verdict = verify_token(
            &test_pki::encode_token(&parts, &authority.tsa_key),
            &basis_of(&bundle, MANIFEST_BYTES),
        );
        assert!(matches!(verdict, Err(Error::NoTrustAnchors)));
    }

    #[test]
    fn an_unrelated_anchor_fails_the_chain() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let stranger = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 7,
                issuer: test_pki::parse_name("CN=Stranger Root"),
                subject: test_pki::parse_name("CN=Stranger Root"),
                key_info: test_pki::key_info_of(
                    &test_pki::signing_key_from_seed(0x33),
                ),
                validity: test_pki::standard_validity(),
                extensions: test_pki::ca_extensions(),
            },
            &test_pki::signing_key_from_seed(0x33),
        );
        let mut bundle = test_pki::standard_trust_ders(&authority);
        bundle.anchors = vec![test_pki::der_of(&stranger)];
        let verdict = verify_token(
            &test_pki::encode_token(&parts, &authority.tsa_key),
            &basis_of(&bundle, MANIFEST_BYTES),
        );
        assert!(matches!(
            verdict,
            Err(Error::UntrustedChain(path::Error::NoTrustedIssuer { .. }))
        ));
    }

    #[test]
    fn a_non_critical_extended_key_usage_fails() {
        let authority = test_pki::authority_with_tsa_extensions(vec![
            test_pki::extension_of(
                &ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]),
                false,
            ),
            test_pki::extension_of(
                &KeyUsage(KeyUsages::DigitalSignature.into()),
                true,
            ),
        ]);
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnfitExtendedKeyUsage)
        ));
    }

    #[test]
    fn an_extended_key_usage_with_extra_purposes_fails() {
        let server_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        let authority = test_pki::authority_with_tsa_extensions(vec![
            test_pki::extension_of(
                &ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING, server_auth]),
                true,
            ),
            test_pki::extension_of(
                &KeyUsage(KeyUsages::DigitalSignature.into()),
                true,
            ),
        ]);
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnfitExtendedKeyUsage)
        ));
    }

    #[test]
    fn a_missing_extended_key_usage_fails() {
        let authority = test_pki::authority_with_tsa_extensions(vec![
            test_pki::extension_of(
                &KeyUsage(KeyUsages::DigitalSignature.into()),
                true,
            ),
        ]);
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UnfitExtendedKeyUsage)
        ));
    }

    #[test]
    fn a_key_usage_without_signing_fails() {
        let authority = test_pki::authority_with_tsa_extensions(vec![
            test_pki::extension_of(
                &ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]),
                true,
            ),
            test_pki::extension_of(
                &KeyUsage(KeyUsages::KeyEncipherment.into()),
                true,
            ),
        ]);
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::ForbiddenKeyUsage)
        ));
    }

    #[test]
    fn a_signer_expired_at_gen_time_fails() {
        let authority = test_pki::authority_with_tsa_blueprint(|blueprint| {
            blueprint.validity = test_pki::validity_between(
                test_pki::GEN_TIME_UNIX_SECONDS - 200 * test_pki::DAY_SECONDS,
                test_pki::GEN_TIME_UNIX_SECONDS - 100 * test_pki::DAY_SECONDS,
            );
        });
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        assert!(matches!(
            verify_against(&parts, &authority),
            Err(Error::UntrustedChain(path::Error::OutsideValidity { .. }))
        ));
    }

    #[test]
    fn a_signer_revoked_before_gen_time_fails() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.entries = vec![test_pki::revoked_entry(
            2,
            test_pki::moment_at(
                test_pki::GEN_TIME_UNIX_SECONDS - test_pki::HOUR_SECONDS,
            ),
            Some(x509_cert::ext::pkix::CrlReason::Superseded),
        )];
        let mut bundle = test_pki::standard_trust_ders(&authority);
        bundle.crls = vec![test_pki::der_of(&test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        ))];
        let verdict = verify_token(
            &test_pki::encode_token(&parts, &authority.tsa_key),
            &basis_of(&bundle, MANIFEST_BYTES),
        );
        assert!(matches!(
            verdict,
            Err(Error::UntrustedChain(path::Error::Revocation(
                revocation::Error::RevokedAtGenTime { .. }
            )))
        ));
    }

    #[test]
    fn a_benign_revocation_after_gen_time_keeps_the_token() {
        let authority = test_pki::standard_authority();
        let parts = test_pki::standard_token_parts(MANIFEST_BYTES, &authority);
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.entries = vec![test_pki::revoked_entry(
            2,
            test_pki::moment_at(
                test_pki::GEN_TIME_UNIX_SECONDS + test_pki::HOUR_SECONDS,
            ),
            Some(x509_cert::ext::pkix::CrlReason::CessationOfOperation),
        )];
        let mut bundle = test_pki::standard_trust_ders(&authority);
        bundle.crls = vec![test_pki::der_of(&test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        ))];
        let verdict = verify_token(
            &test_pki::encode_token(&parts, &authority.tsa_key),
            &basis_of(&bundle, MANIFEST_BYTES),
        );
        assert!(verdict.is_ok());
    }

    const RECORD_FIXTURES_ENV: &str = "TYDENCE_RECORD_FREETSA";

    // The payload the stage-3 cassettes were recorded over; the
    // replay tests there pin the same bytes. A drift between the two
    // spellings surfaces loudly as an imprint mismatch here.
    const FIXTURE_PAYLOAD: &[u8] = b"tydence freetsa fixture payload\n";

    fn fixture_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/freetsa")
            .join(name)
    }

    fn record_freetsa_file(fixture_file: &Path, url: &str) {
        let fetched_bytes =
            transport::fetch(url).expect("the freeTSA trust material fetches");
        fs::write(fixture_file, &fetched_bytes)
            .expect("the fixture file writes");
    }

    /// Provides one freeTSA trust-material fixture, PEM as served,
    /// converted to DER on load. The mode is decided by
    /// [`RECORD_FIXTURES_ENV`] alone, exactly like the stage-3
    /// cassettes: when set, the fixture is re-fetched over the
    /// network unconditionally; when unset, the recording is used,
    /// and a missing file fails with an instruction to re-record.
    /// One piece of freeTSA trust material and where it lives, so
    /// call sites cannot transpose the three strings silently.
    struct FixtureSource {
        file_name: &'static str,
        url: &'static str,
        pem_label: &'static str,
    }

    const ROOT_CERTIFICATE_SOURCE: FixtureSource = FixtureSource {
        file_name: "root-ca.pem",
        url: "https://freetsa.org/files/cacert.pem",
        pem_label: "CERTIFICATE",
    };

    const ROOT_CRL_SOURCE: FixtureSource = FixtureSource {
        file_name: "root-ca.crl",
        url: "https://freetsa.org/crl/root_ca.crl",
        pem_label: "X509 CRL",
    };

    fn freetsa_trust_fixture(source: &FixtureSource) -> Vec<u8> {
        let fixture_file = fixture_path(source.file_name);
        if std::env::var_os(RECORD_FIXTURES_ENV).is_some() {
            record_freetsa_file(&fixture_file, source.url);
        }
        let pem_text =
            fs::read_to_string(&fixture_file).unwrap_or_else(|read_error| {
                panic!(
                    "the freeTSA fixture file {} is unreadable \
                     ({read_error}); rerun the tests once with \
                     {RECORD_FIXTURES_ENV}=1 to record the fixtures \
                     over the network",
                    fixture_file.display()
                )
            });
        let (label, document) =
            der::Document::from_pem(&pem_text).expect("the fixture is PEM");
        assert_eq!(label, source.pem_label);
        document.into_vec()
    }

    fn freetsa_root_der() -> Vec<u8> {
        freetsa_trust_fixture(&ROOT_CERTIFICATE_SOURCE)
    }

    fn freetsa_crl_der() -> Vec<u8> {
        freetsa_trust_fixture(&ROOT_CRL_SOURCE)
    }

    fn freetsa_token_from_cassette(name: &str) -> Vec<u8> {
        let cassette_file = fixture_path(&format!("{name}.tsr"));
        let response_bytes =
            fs::read(&cassette_file).unwrap_or_else(|read_error| {
                panic!(
                    "the freeTSA cassette {} is unreadable ({read_error})",
                    cassette_file.display()
                )
            });
        let response = TimeStampResp::from_der(&response_bytes)
            .expect("the cassette response parses");
        let token = response
            .time_stamp_token
            .expect("the cassette response carries a token");
        token.to_der().expect("the cassette token re-encodes")
    }

    fn freetsa_verdict(
        cassette_name: &str,
        manifest_bytes: &[u8],
        crls: Vec<Vec<u8>>,
    ) -> Result<TokenSummary, Error> {
        let anchors = vec![freetsa_root_der()];
        verify_token(
            &freetsa_token_from_cassette(cassette_name),
            &VerificationBasis {
                manifest_bytes,
                trust: TrustData {
                    anchor_certificates: &anchors,
                    companion_certificates: &[],
                    crls: &crls,
                },
            },
        )
    }

    #[test]
    fn the_freetsa_sha256_token_verifies_end_to_end() {
        let summary = freetsa_verdict(
            "sha256",
            FIXTURE_PAYLOAD,
            vec![freetsa_crl_der()],
        )
        .expect("the recorded token verifies");
        assert_eq!(summary.imprint_algorithm, ImprintAlgorithm::Sha256);
    }

    #[test]
    fn the_freetsa_sha512_token_verifies_end_to_end() {
        let summary = freetsa_verdict(
            "sha512",
            FIXTURE_PAYLOAD,
            vec![freetsa_crl_der()],
        )
        .expect("the recorded token verifies");
        assert_eq!(summary.imprint_algorithm, ImprintAlgorithm::Sha512);
    }

    #[test]
    fn the_freetsa_token_refuses_a_different_manifest() {
        let verdict =
            freetsa_verdict("sha256", b"other bytes", vec![freetsa_crl_der()]);
        assert!(matches!(verdict, Err(Error::ImprintMismatch)));
    }

    #[test]
    fn the_freetsa_token_is_undecidable_without_the_sealed_crl() {
        let verdict = freetsa_verdict("sha256", FIXTURE_PAYLOAD, vec![]);
        assert!(matches!(
            verdict,
            Err(Error::UntrustedChain(path::Error::Revocation(
                revocation::Error::NoUsableCrl
            )))
        ));
    }
}
