//! Object identifiers shared by the TSP client and the verifier.
//!
//! The constants are declared locally: const-oid's database module
//! sits behind a feature nothing in this dependency graph enables,
//! and it lacks id-ct-TSTInfo altogether.

use der::oid::ObjectIdentifier;

/// id-sha1 (RFC 3370 §2.1). Certificate identification in legacy
/// ESSCertID attributes only; never an evidence hash.
pub const ID_SHA_1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// id-sha256 (RFC 5754 §2).
pub const ID_SHA_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// id-sha384 (RFC 5754 §2).
pub const ID_SHA_384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// id-sha512 (RFC 5754 §2).
pub const ID_SHA_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// rsaEncryption (RFC 8017 §A.1): names the bare key type when a
/// CMS SignerInfo splits the digest off into its own field.
pub const ID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// sha256WithRSAEncryption (RFC 5754 §3.2).
pub const ID_SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// sha384WithRSAEncryption (RFC 5754 §3.2).
pub const ID_SHA_384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

/// sha512WithRSAEncryption (RFC 5754 §3.2).
pub const ID_SHA_512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// ecdsa-with-SHA256 (RFC 5754 §3.3).
pub const ID_ECDSA_WITH_SHA_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA384 (RFC 5754 §3.3).
pub const ID_ECDSA_WITH_SHA_384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// ecdsa-with-SHA512 (RFC 5754 §3.3).
pub const ID_ECDSA_WITH_SHA_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// id-signedData (RFC 5652 §5.1).
pub const ID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// id-ct-TSTInfo (RFC 3161 §2.4.2).
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// id-contentType (RFC 5652 §11.1).
pub const ID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// id-messageDigest (RFC 5652 §11.2).
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// id-aa-signingCertificate (RFC 2634 §5.4).
pub const ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

/// id-aa-signingCertificateV2 (RFC 5035 §3).
pub const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// id-kp-timeStamping (RFC 3161 §2.3).
pub const ID_KP_TIME_STAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
