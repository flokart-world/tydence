//! Enhanced Security Services certificate identification: ESSCertID
//! (RFC 2634 §5.4) and ESSCertIDv2 (RFC 5035 §4).
//!
//! RFC 3161 makes the signing-certificate attribute mandatory in
//! every token, and RFC 5816 obliges verifiers to accept both
//! generations, so both are declared here — no crate in the stable
//! RustCrypto formats line ships them.

use der::asn1::OctetString;
use der::{Any, Sequence};
use x509_cert::ext::pkix::name::GeneralNames;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

/// IssuerSerial (RFC 5035 §4).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IssuerSerial {
    pub issuer: GeneralNames,
    pub serial_number: SerialNumber,
}

/// ESSCertID (RFC 2634 §5.4.1). The certificate hash is fixed to
/// SHA-1 by the structure itself; it identifies the certificate and
/// carries no evidential weight.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertId {
    pub cert_hash: OctetString,
    pub issuer_serial: Option<IssuerSerial>,
}

/// ESSCertIDv2 (RFC 5035 §4). An absent hash algorithm means the
/// DEFAULT, SHA-256; DER forbids writing the default out, so `None`
/// is the only spelling of it a valid encoding can carry.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub cert_hash: OctetString,
    pub issuer_serial: Option<IssuerSerial>,
}

/// SigningCertificate (RFC 2634 §5.4). The policies are carried
/// opaquely: they do not participate in certificate identification.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificate {
    pub certs: Vec<EssCertId>,
    pub policies: Option<Vec<Any>>,
}

/// SigningCertificateV2 (RFC 5035 §3).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
    pub policies: Option<Vec<Any>>,
}

#[cfg(test)]
use super::oids;

#[cfg(test)]
mod tests {
    use der::{Decode, Encode};

    use super::oids::ID_SHA_384;

    use super::*;

    fn octets(fill_byte: u8, count: usize) -> OctetString {
        OctetString::new(vec![fill_byte; count])
            .expect("short octet strings encode")
    }

    #[test]
    fn a_v1_attribute_round_trips_without_optional_fields() {
        let original = SigningCertificate {
            certs: vec![EssCertId {
                cert_hash: octets(0xAB, 20),
                issuer_serial: None,
            }],
            policies: None,
        };
        let encoded = original.to_der().expect("the structure encodes");
        assert_eq!(SigningCertificate::from_der(&encoded), Ok(original));
    }

    #[test]
    fn a_v2_attribute_with_absent_algorithm_reads_back_as_none() {
        let original = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None,
                cert_hash: octets(0xCD, 32),
                issuer_serial: None,
            }],
            policies: None,
        };
        let encoded = original.to_der().expect("the structure encodes");
        let decoded = SigningCertificateV2::from_der(&encoded)
            .expect("the encoding parses");
        assert_eq!(decoded.certs[0].hash_algorithm, None);
        assert_eq!(decoded, original);
    }

    #[test]
    fn a_hand_written_v1_encoding_decodes_and_reencodes_byte_for_byte() {
        // SigningCertificate { certs: [ ESSCertID { certHash } ] },
        // spelled out by hand so the check does not lean on the same
        // derive that produced it: SEQUENCE / SEQUENCE OF / SEQUENCE
        // / OCTET STRING with a 20-byte SHA-1-sized hash.
        let mut encoded = vec![0x30, 0x1A, 0x30, 0x18, 0x30, 0x16];
        encoded.extend([0x04, 0x14]);
        encoded.extend([0xCD; 20]);
        let decoded = SigningCertificate::from_der(&encoded)
            .expect("the hand-written encoding parses");
        assert_eq!(
            decoded,
            SigningCertificate {
                certs: vec![EssCertId {
                    cert_hash: octets(0xCD, 20),
                    issuer_serial: None,
                }],
                policies: None,
            }
        );
        assert_eq!(decoded.to_der(), Ok(encoded));
    }

    #[test]
    fn a_hand_written_v2_encoding_decodes_and_reencodes_byte_for_byte() {
        // SigningCertificateV2 { certs: [ ESSCertIDv2 { certHash } ] }
        // with the hash algorithm absent (DEFAULT sha256), so the
        // OPTIONAL-field handling is pinned against fixed bytes.
        let mut encoded = vec![0x30, 0x26, 0x30, 0x24, 0x30, 0x22];
        encoded.extend([0x04, 0x20]);
        encoded.extend([0xAB; 32]);
        let decoded = SigningCertificateV2::from_der(&encoded)
            .expect("the hand-written encoding parses");
        assert_eq!(
            decoded,
            SigningCertificateV2 {
                certs: vec![EssCertIdV2 {
                    hash_algorithm: None,
                    cert_hash: octets(0xAB, 32),
                    issuer_serial: None,
                }],
                policies: None,
            }
        );
        assert_eq!(decoded.to_der(), Ok(encoded));
    }

    #[test]
    fn a_v2_attribute_with_an_explicit_algorithm_keeps_it() {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ID_SHA_384,
            parameters: None,
        };
        let original = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: Some(algorithm.clone()),
                cert_hash: octets(0xEF, 48),
                issuer_serial: None,
            }],
            policies: None,
        };
        let encoded = original.to_der().expect("the structure encodes");
        let decoded = SigningCertificateV2::from_der(&encoded)
            .expect("the encoding parses");
        assert_eq!(decoded.certs[0].hash_algorithm, Some(algorithm));
    }
}
