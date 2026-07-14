//! Synthetic PKI for verification tests: a P-256 root authority, a
//! TSA certificate under it, CRLs and hand-assembled tokens.
//!
//! Keys derive from fixed scalars and ECDSA signing is RFC 6979
//! deterministic, so every fixture is reproducible without any RNG.
//! The pieces are exposed separately so each test can assemble the
//! exact defect it specifies.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier,
    SignerInfo, SignerInfos,
};
use der::asn1::{GeneralizedTime, Ia5String, Int, OctetString, SetOfVec};
use der::{Any, Encode, Tag};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::attr::Attribute;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    BasicConstraints, CrlDistributionPoints, CrlReason, ExtendedKeyUsage,
    KeyUsage, KeyUsages,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate, Version};
use x509_tsp::{MessageImprint, TspVersion, TstInfo};

use super::ess::{
    EssCertId, EssCertIdV2, SigningCertificate, SigningCertificateV2,
};
use super::oids::{
    ID_AA_SIGNING_CERTIFICATE, ID_AA_SIGNING_CERTIFICATE_V2, ID_CONTENT_TYPE,
    ID_CT_TST_INFO, ID_ECDSA_WITH_SHA_256, ID_KP_TIME_STAMPING,
    ID_MESSAGE_DIGEST, ID_SHA_256, ID_SIGNED_DATA,
};

pub const GEN_TIME_UNIX_SECONDS: u64 = 1_780_000_000;
pub const ROOT_NAME: &str = "CN=Tydence Test Root";
pub const TSA_NAME: &str = "CN=Tydence Test TSA";

pub const DAY_SECONDS: u64 = 86_400;
pub const HOUR_SECONDS: u64 = 3_600;

pub fn moment_at(unix_seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(unix_seconds)
}

pub fn gen_time_moment() -> SystemTime {
    moment_at(GEN_TIME_UNIX_SECONDS)
}

pub fn parse_name(text: &str) -> Name {
    Name::from_str(text).expect("test names parse")
}

pub fn der_of<Value: Encode>(value: &Value) -> Vec<u8> {
    value.to_der().expect("test structures encode")
}

pub fn signing_key_from_seed(seed_byte: u8) -> SigningKey {
    // Any nonzero scalar below the curve order works as a key, so a
    // repeated seed byte gives distinct deterministic keys.
    SigningKey::from_slice(&[seed_byte; 32]).expect("test scalars are keys")
}

/// id-ecPublicKey (RFC 5480 §2.1.1).
const ID_EC_PUBLIC_KEY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// secp256r1 (RFC 5480 §2.1.1.1).
const ID_SECP_256_R_1: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

// Assembled by hand from the uncompressed SEC1 point: the trait that
// would do it hides behind an unrelated PEM feature of the ecdsa
// crate.
pub fn key_info_of(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    let point = key.verifying_key().to_encoded_point(false);
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(
                Any::encode_from(&ID_SECP_256_R_1)
                    .expect("curve identifiers encode"),
            ),
        },
        subject_public_key: der::asn1::BitString::from_bytes(point.as_bytes())
            .expect("SEC1 points fit a BIT STRING"),
    }
}

pub fn sign_der_message(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: EcdsaSignature = key.sign(message);
    signature.to_der().as_ref().to_vec()
}

pub fn ecdsa_sha256_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_ECDSA_WITH_SHA_256,
        parameters: None,
    }
}

pub fn sha256_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    }
}

pub fn extension_of<Value>(value: &Value, critical: bool) -> Extension
where
    Value: Encode + der::oid::AssociatedOid,
{
    Extension {
        extn_id: Value::OID,
        critical,
        extn_value: OctetString::new(der_of(value))
            .expect("extension values encode"),
    }
}

pub fn ca_extensions() -> Vec<Extension> {
    vec![
        extension_of(
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            true,
        ),
        extension_of(
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            true,
        ),
    ]
}

pub fn tsa_extensions() -> Vec<Extension> {
    vec![
        extension_of(&ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]), true),
        extension_of(&KeyUsage(KeyUsages::DigitalSignature.into()), true),
    ]
}

/// The standard authority whose TSA certificate also advertises
/// `url` as its CRL distribution point. Keys derive from fixed
/// scalars, so two calls yield byte-identical certificates: a
/// serving thread and a test's assertions can each build their own.
pub fn authority_with_crl_distribution(url: &str) -> Authority {
    let mut extensions = tsa_extensions();
    extensions.push(crl_distribution_extension(url));
    authority_with_tsa_extensions(extensions)
}

/// A CRL distribution point naming one URI, for chains whose CRLs
/// tests serve over loopback HTTP.
pub fn crl_distribution_extension(url: &str) -> Extension {
    let points = CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(
                Ia5String::new(url).expect("the URL spells as IA5"),
            ),
        ])),
        reasons: None,
        crl_issuer: None,
    }]);
    extension_of(&points, false)
}

/// Validity window comfortably containing the fixed genTime.
pub fn standard_validity() -> Validity {
    validity_between(
        GEN_TIME_UNIX_SECONDS - 400 * DAY_SECONDS,
        GEN_TIME_UNIX_SECONDS + 3_650 * DAY_SECONDS,
    )
}

pub fn validity_between(
    from_unix_seconds: u64,
    to_unix_seconds: u64,
) -> Validity {
    Validity {
        not_before: moment_at(from_unix_seconds)
            .try_into()
            .expect("test moments are representable"),
        not_after: moment_at(to_unix_seconds)
            .try_into()
            .expect("test moments are representable"),
    }
}

pub struct CertificateBlueprint {
    pub serial_byte: u8,
    pub issuer: Name,
    pub subject: Name,
    pub key_info: SubjectPublicKeyInfoOwned,
    pub validity: Validity,
    pub extensions: Vec<Extension>,
}

pub fn issue_certificate(
    blueprint: CertificateBlueprint,
    issuer_key: &SigningKey,
) -> Certificate {
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[blueprint.serial_byte])
            .expect("single-byte serials encode"),
        signature: ecdsa_sha256_identifier(),
        issuer: blueprint.issuer,
        validity: blueprint.validity,
        subject: blueprint.subject,
        subject_public_key_info: blueprint.key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(blueprint.extensions),
    };
    let signature_bytes = sign_der_message(issuer_key, &der_of(&tbs));
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256_identifier(),
        signature: der::asn1::BitString::from_bytes(&signature_bytes)
            .expect("signatures fit a BIT STRING"),
    }
}

/// The synthetic chain the standard fixtures use: a self-signed root
/// and a timestamping certificate under it.
pub struct Authority {
    pub root_certificate: Certificate,
    pub root_key: SigningKey,
    pub tsa_certificate: Certificate,
    pub tsa_key: SigningKey,
}

pub fn authority_with_tsa_blueprint(
    adjust: impl FnOnce(&mut CertificateBlueprint),
) -> Authority {
    let root_key = signing_key_from_seed(0x11);
    let tsa_key = signing_key_from_seed(0x22);
    let root_certificate = issue_certificate(
        CertificateBlueprint {
            serial_byte: 1,
            issuer: parse_name(ROOT_NAME),
            subject: parse_name(ROOT_NAME),
            key_info: key_info_of(&root_key),
            validity: standard_validity(),
            extensions: ca_extensions(),
        },
        &root_key,
    );
    let mut tsa_blueprint = CertificateBlueprint {
        serial_byte: 2,
        issuer: parse_name(ROOT_NAME),
        subject: parse_name(TSA_NAME),
        key_info: key_info_of(&tsa_key),
        validity: standard_validity(),
        extensions: tsa_extensions(),
    };
    adjust(&mut tsa_blueprint);
    let tsa_certificate = issue_certificate(tsa_blueprint, &root_key);
    Authority {
        root_certificate,
        root_key,
        tsa_certificate,
        tsa_key,
    }
}

pub fn authority_with_tsa_extensions(extensions: Vec<Extension>) -> Authority {
    authority_with_tsa_blueprint(|blueprint| {
        blueprint.extensions = extensions;
    })
}

pub fn standard_authority() -> Authority {
    authority_with_tsa_blueprint(|_| {})
}

pub fn revoked_entry(
    serial_byte: u8,
    revoked_at: SystemTime,
    reason: Option<CrlReason>,
) -> RevokedCert {
    let extensions =
        reason.map(|known_reason| vec![extension_of(&known_reason, false)]);
    RevokedCert {
        serial_number: SerialNumber::new(&[serial_byte])
            .expect("single-byte serials encode"),
        revocation_date: revoked_at
            .try_into()
            .expect("test moments are representable"),
        crl_entry_extensions: extensions,
    }
}

pub struct CrlBlueprint {
    pub this_update_unix_seconds: u64,
    pub next_update_unix_seconds: Option<u64>,
    pub entries: Vec<RevokedCert>,
    pub extensions: Option<Vec<Extension>>,
}

pub fn standard_crl_blueprint() -> CrlBlueprint {
    CrlBlueprint {
        this_update_unix_seconds: GEN_TIME_UNIX_SECONDS - DAY_SECONDS,
        next_update_unix_seconds: Some(
            GEN_TIME_UNIX_SECONDS + 30 * DAY_SECONDS,
        ),
        entries: vec![],
        extensions: None,
    }
}

pub fn issue_crl(
    blueprint: CrlBlueprint,
    issuer: &Certificate,
    issuer_key: &SigningKey,
) -> CertificateList {
    let tbs = TbsCertList {
        version: Version::V2,
        signature: ecdsa_sha256_identifier(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: moment_at(blueprint.this_update_unix_seconds)
            .try_into()
            .expect("test moments are representable"),
        next_update: blueprint.next_update_unix_seconds.map(|unix_seconds| {
            moment_at(unix_seconds)
                .try_into()
                .expect("test moments are representable")
        }),
        revoked_certificates: Some(blueprint.entries),
        crl_extensions: blueprint.extensions,
    };
    let signature_bytes = sign_der_message(issuer_key, &der_of(&tbs));
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: ecdsa_sha256_identifier(),
        signature: der::asn1::BitString::from_bytes(&signature_bytes)
            .expect("signatures fit a BIT STRING"),
    }
}

pub fn standard_crl(authority: &Authority) -> CertificateList {
    issue_crl(
        standard_crl_blueprint(),
        &authority.root_certificate,
        &authority.root_key,
    )
}

pub fn standard_tst_info(manifest_bytes: &[u8]) -> TstInfo {
    TstInfo {
        version: TspVersion::V1,
        policy: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.1"),
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: Some(Any::null()),
            },
            hashed_message: OctetString::new(
                Sha256::digest(manifest_bytes).to_vec(),
            )
            .expect("digests encode"),
        },
        serial_number: Int::new(&[0x2A]).expect("small serials encode"),
        gen_time: GeneralizedTime::from_unix_duration(Duration::from_secs(
            GEN_TIME_UNIX_SECONDS,
        ))
        .expect("the fixed genTime is representable"),
        accuracy: None,
        ordering: false,
        nonce: None,
        tsa: None,
        extensions: None,
    }
}

pub fn attribute_of<Value: der::Tagged + der::EncodeValue>(
    oid: der::asn1::ObjectIdentifier,
    value: &Value,
) -> Attribute {
    let mut values = SetOfVec::new();
    values
        .insert(Any::encode_from(value).expect("attribute values encode"))
        .expect("fresh sets accept a value");
    Attribute { oid, values }
}

pub fn signing_certificate_v1_attribute(
    signer_certificate: &Certificate,
) -> Attribute {
    use sha1::Sha1;
    let attribute = SigningCertificate {
        certs: vec![EssCertId {
            cert_hash: OctetString::new(
                Sha1::digest(der_of(signer_certificate)).to_vec(),
            )
            .expect("digests encode"),
            issuer_serial: None,
        }],
        policies: None,
    };
    attribute_of(ID_AA_SIGNING_CERTIFICATE, &attribute)
}

pub fn signing_certificate_v2_attribute(
    signer_certificate: &Certificate,
) -> Attribute {
    let attribute = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: None,
            cert_hash: OctetString::new(
                Sha256::digest(der_of(signer_certificate)).to_vec(),
            )
            .expect("digests encode"),
            issuer_serial: None,
        }],
        policies: None,
    };
    attribute_of(ID_AA_SIGNING_CERTIFICATE_V2, &attribute)
}

pub fn standard_attributes(
    content_bytes: &[u8],
    signer_certificate: &Certificate,
) -> SetOfVec<Attribute> {
    let mut attributes = SetOfVec::new();
    attributes
        .insert(attribute_of(ID_CONTENT_TYPE, &ID_CT_TST_INFO))
        .expect("distinct attributes insert");
    attributes
        .insert(attribute_of(
            ID_MESSAGE_DIGEST,
            &OctetString::new(Sha256::digest(content_bytes).to_vec())
                .expect("digests encode"),
        ))
        .expect("distinct attributes insert");
    attributes
        .insert(signing_certificate_v2_attribute(signer_certificate))
        .expect("distinct attributes insert");
    attributes
}

/// The pieces a token is assembled from, pre-assembled to the
/// standard shape so each test mutates exactly the defect it
/// specifies before encoding.
pub struct TokenParts {
    pub econtent_type: der::asn1::ObjectIdentifier,
    pub content_bytes: Vec<u8>,
    pub digest_algorithm: AlgorithmIdentifierOwned,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub attributes: SetOfVec<Attribute>,
    pub certificates: Vec<Certificate>,
    pub sid: SignerIdentifier,
    pub signer_version: CmsVersion,
    /// Replaces the computed signature when set, so tampering does
    /// not have to break the DER structure.
    pub signature_override: Option<Vec<u8>>,
    /// Drops the signed attributes from the SignerInfo while still
    /// signing over them, isolating their absence as the defect.
    pub omit_signed_attributes: bool,
}

pub fn standard_token_parts(
    manifest_bytes: &[u8],
    authority: &Authority,
) -> TokenParts {
    let content_bytes = der_of(&standard_tst_info(manifest_bytes));
    let attributes =
        standard_attributes(&content_bytes, &authority.tsa_certificate);
    TokenParts {
        econtent_type: ID_CT_TST_INFO,
        content_bytes,
        digest_algorithm: sha256_identifier(),
        signature_algorithm: ecdsa_sha256_identifier(),
        attributes,
        certificates: vec![
            authority.tsa_certificate.clone(),
            authority.root_certificate.clone(),
        ],
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: authority.tsa_certificate.tbs_certificate.issuer.clone(),
            serial_number: authority
                .tsa_certificate
                .tbs_certificate
                .serial_number
                .clone(),
        }),
        signer_version: CmsVersion::V1,
        signature_override: None,
        omit_signed_attributes: false,
    }
}

pub fn encode_token(parts: &TokenParts, signer_key: &SigningKey) -> Vec<u8> {
    let message = der_of(&parts.attributes);
    let signature_bytes = parts
        .signature_override
        .clone()
        .unwrap_or_else(|| sign_der_message(signer_key, &message));
    let signer_info = SignerInfo {
        version: parts.signer_version,
        sid: parts.sid.clone(),
        digest_alg: parts.digest_algorithm.clone(),
        signed_attrs: (!parts.omit_signed_attributes)
            .then(|| parts.attributes.clone()),
        signature_algorithm: parts.signature_algorithm.clone(),
        signature: OctetString::new(signature_bytes)
            .expect("signatures encode"),
        unsigned_attrs: None,
    };
    let mut signer_set = SetOfVec::new();
    signer_set
        .insert(signer_info)
        .expect("fresh sets accept a value");
    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms
        .insert(parts.digest_algorithm.clone())
        .expect("fresh sets accept a value");
    let mut certificate_choices = SetOfVec::new();
    for certificate in &parts.certificates {
        certificate_choices
            .insert(CertificateChoices::Certificate(certificate.clone()))
            .expect("distinct certificates insert");
    }
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: parts.econtent_type,
            econtent: Some(
                Any::new(Tag::OctetString, parts.content_bytes.clone())
                    .expect("content bytes wrap"),
            ),
        },
        certificates: Some(CertificateSet(certificate_choices)),
        crls: None,
        signer_infos: SignerInfos(signer_set),
    };
    let token = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).expect("signed data encodes"),
    };
    der_of(&token)
}

/// DER bundle for a [`super::TrustData`] pointing at the authority's
/// root with its standard empty CRL.
pub struct TrustDers {
    pub anchors: Vec<Vec<u8>>,
    pub companions: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

pub fn standard_trust_ders(authority: &Authority) -> TrustDers {
    TrustDers {
        anchors: vec![der_of(&authority.root_certificate)],
        companions: vec![],
        crls: vec![der_of(&standard_crl(authority))],
    }
}
