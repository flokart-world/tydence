//! Trust material supply: decoding the PEM forms tydence exchanges
//! with the outside — trust anchor certificates handed to stamping
//! and verification (never taken from the repository, which must not
//! certify itself), and the `ltv/` chain and CRL records the
//! stamping specification §3 stores PEM-encoded.

use der::Encode;
use std::fmt;
use std::path::Path;
use x509_cert::Certificate;

// The stable x509-cert line gives CertificateList no PEM label, so
// the label is pinned here and the framing handled with pem-rfc7468
// directly.
pub const CRL_PEM_LABEL: &str = "X509 CRL";

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// A trust material file could not be read from disk.
    Unreadable { path: String, source: FailureCause },
    /// Bytes that should be PEM-encoded trust material do not decode
    /// to it.
    Malformed {
        description: String,
        source: FailureCause,
    },
    /// A PEM that decoded cleanly holds no certificate at all, so it
    /// supplies nothing to trust.
    Empty { description: String },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, .. } => {
                write!(formatter, "cannot read trust material at {path:?}")
            }
            Self::Malformed { description, .. } => {
                write!(formatter, "{description} is not valid PEM material")
            }
            Self::Empty { description } => {
                write!(formatter, "{description} holds no certificate")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. }
            | Self::Malformed { source, .. } => Some(source.as_ref()),
            Self::Empty { .. } => None,
        }
    }
}

/// Decodes a PEM certificate bundle — one or more concatenated
/// `CERTIFICATE` blocks — into the DER bytes of each certificate.
pub fn certificates_from_pem(
    pem_bytes: &[u8],
    description: &str,
) -> Result<Vec<Vec<u8>>, Error> {
    let malformed = |source: FailureCause| Error::Malformed {
        description: description.to_string(),
        source,
    };
    // Guarded here because load_pem_chain panics on empty input
    // (x509-cert 0.2.5 subtracts past zero) instead of erroring.
    if pem_bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(Error::Empty {
            description: description.to_string(),
        });
    }
    let certificates = Certificate::load_pem_chain(pem_bytes)
        .map_err(|source| malformed(Box::new(source)))?;
    if certificates.is_empty() {
        return Err(Error::Empty {
            description: description.to_string(),
        });
    }
    certificates
        .iter()
        .map(|certificate| {
            certificate
                .to_der()
                .map_err(|source| malformed(Box::new(source)))
        })
        .collect()
}

/// Decodes one PEM-framed CRL snapshot into its DER bytes.
pub fn crl_from_pem(
    pem_bytes: &[u8],
    description: &str,
) -> Result<Vec<u8>, Error> {
    let malformed = |source: FailureCause| Error::Malformed {
        description: description.to_string(),
        source,
    };
    let (label, der_bytes) = pem_rfc7468::decode_vec(pem_bytes)
        .map_err(|source| malformed(Box::new(source)))?;
    if label != CRL_PEM_LABEL {
        return Err(malformed(
            format!("PEM label {label:?} is not {CRL_PEM_LABEL:?}").into(),
        ));
    }
    Ok(der_bytes)
}

/// Reads one anchor PEM file into the DER bytes of its certificates.
pub fn load_anchor_file(path: &Path) -> Result<Vec<Vec<u8>>, Error> {
    let pem_bytes =
        std::fs::read(path).map_err(|source| Error::Unreadable {
            path: path.display().to_string(),
            source: Box::new(source),
        })?;
    certificates_from_pem(&pem_bytes, &path.display().to_string())
}

#[cfg(test)]
use super::test_pki;

#[cfg(test)]
mod tests {
    use der::EncodePem;
    use std::fs;

    use super::test_pki;

    use super::*;

    fn root_pem() -> String {
        let authority = test_pki::standard_authority();
        authority
            .root_certificate
            .to_pem(pem_rfc7468::LineEnding::LF)
            .expect("the fixture certificate encodes")
    }

    #[test]
    fn a_pem_bundle_yields_each_certificate_der() {
        let authority = test_pki::standard_authority();
        let bundle = format!(
            "{}{}",
            authority
                .root_certificate
                .to_pem(pem_rfc7468::LineEnding::LF)
                .expect("the fixture certificate encodes"),
            authority
                .tsa_certificate
                .to_pem(pem_rfc7468::LineEnding::LF)
                .expect("the fixture certificate encodes"),
        );
        let ders = certificates_from_pem(bundle.as_bytes(), "fixture")
            .expect("the bundle decodes");
        assert_eq!(ders.len(), 2);
        assert_eq!(
            ders[0],
            authority
                .root_certificate
                .to_der()
                .expect("the fixture certificate encodes")
        );
    }

    #[test]
    fn an_empty_pem_supplies_nothing_to_trust() {
        let verdict = certificates_from_pem(b"", "fixture");
        assert!(matches!(verdict, Err(Error::Empty { .. })));
    }

    #[test]
    fn a_crl_pem_round_trips_to_der() {
        let der_bytes = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let pem_text = pem_rfc7468::encode_string(
            CRL_PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            &der_bytes,
        )
        .expect("the fixture CRL encodes");
        let decoded = crl_from_pem(pem_text.as_bytes(), "fixture")
            .expect("the CRL PEM decodes");
        assert_eq!(decoded, der_bytes);
    }

    #[test]
    fn a_mislabeled_crl_pem_is_refused() {
        let pem_text = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &[0x30, 0x03, 0x02, 0x01, 0x01],
        )
        .expect("the fixture encodes");
        let verdict = crl_from_pem(pem_text.as_bytes(), "fixture");
        assert!(matches!(verdict, Err(Error::Malformed { .. })));
    }

    #[test]
    fn an_anchor_file_loads_its_certificates() {
        let directory = tempfile::tempdir().expect("tempdir");
        let anchor_file = directory.path().join("root.pem");
        fs::write(&anchor_file, root_pem()).expect("the anchor writes");
        let anchors =
            load_anchor_file(&anchor_file).expect("the anchor file loads");
        assert_eq!(anchors.len(), 1);
    }

    #[test]
    fn a_missing_anchor_file_is_unreadable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let verdict = load_anchor_file(&directory.path().join("absent.pem"));
        assert!(matches!(verdict, Err(Error::Unreadable { .. })));
    }
}
