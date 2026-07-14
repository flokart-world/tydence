//! LTV material acquisition (stamping specification §5): [`refresh`]
//! renews the CRL snapshots for every chain already on record before
//! the manifest is fixed, so the covering stamp seals revocation
//! data of the same moment as its tokens; [`harvest`] gathers the
//! chain a freshly received token carries — with the CRLs its
//! pre-seal verification needs — and [`record`] settles a verified
//! token's harvest in the working tree, where the following stamp
//! seals it (the deferral approved for this design).
//!
//! Files are keyed by `<issuer_hash>`: the lowercase hex SHA-256 of
//! the DER-encoded issuer name. Like a `--commit` annotation the key
//! only organizes files; the evidence is the recorded bytes. The key
//! is write-only by design: no reader ever derives or parses a file
//! name — [`refresh`] and any future verifier enumerate the
//! directories instead — so the derivation can change at any time
//! without touching past stamps or the specification.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::oid::AssociatedOid;
use der::{Decode, Encode, EncodePem};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::name::Name;

use super::hex;
use super::layout::{
    CHAIN_FILE_SUFFIX, CRL_FILE_SUFFIX, LTV_CERTS_PATH, LTV_CRLS_PATH,
};
use super::oids::ID_SIGNED_DATA;
use super::transport;
use super::trust::CRL_PEM_LABEL;

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// The token bytes do not parse as the structure they claim.
    MalformedToken {
        source: FailureCause,
    },
    NotSignedData {
        content_type: String,
    },
    WrongSignerCount {
        count: usize,
    },
    /// The signer identifier carries no issuer name to key the chain
    /// file by. No surveyed TSA identifies its signer by key id; the
    /// keying question returns if one ever does.
    UnkeyableSigner,
    /// The token embeds no certificates although certReq was set.
    MissingCertificates,
    /// The token embeds certificate material in a form other than a
    /// plain certificate, which cannot be recorded as a chain.
    ForeignCertificateForm,
    /// A certificate's CRL distribution points extension does not
    /// parse.
    MalformedDistributionPoints {
        source: FailureCause,
    },
    /// A certificate advertises distribution points, but none in a
    /// shape this implementation can fetch. Distinct from advertising
    /// nothing: revocation data exists and would silently go
    /// uncollected.
    UnusableDistributionPoints {
        subject: String,
    },
    /// Material to record failed to encode.
    Encoding {
        source: FailureCause,
    },
    /// A file under `ltv/` could not be read or written.
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A file under `ltv/certs/` is not a recorded chain.
    ForeignRecord {
        path: PathBuf,
    },
    /// A recorded chain file does not parse as PEM certificates.
    MalformedChainFile {
        path: PathBuf,
        source: FailureCause,
    },
    /// Every distribution point a certificate advertises failed.
    CrlUnavailable {
        subject: String,
        source: FailureCause,
    },
    /// A fetched CRL does not parse.
    MalformedCrl {
        source: FailureCause,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken { .. } => {
                write!(formatter, "the token fails to parse")
            }
            Self::NotSignedData { content_type } => write!(
                formatter,
                "the token is not a CMS SignedData \
                 (content type {content_type})"
            ),
            Self::WrongSignerCount { count } => write!(
                formatter,
                "the token carries {count} signer infos where RFC 3161 \
                 requires exactly one"
            ),
            Self::UnkeyableSigner => write!(
                formatter,
                "the token identifies its signer without an issuer name"
            ),
            Self::MissingCertificates => {
                write!(formatter, "the token embeds no certificates")
            }
            Self::ForeignCertificateForm => write!(
                formatter,
                "the token embeds certificate material that is not a \
                 plain certificate"
            ),
            Self::MalformedDistributionPoints { .. } => write!(
                formatter,
                "a certificate's CRL distribution points do not parse"
            ),
            Self::UnusableDistributionPoints { subject } => write!(
                formatter,
                "no distribution point of {subject:?} is in a fetchable \
                 shape"
            ),
            Self::Encoding { .. } => {
                write!(formatter, "the trust material failed to encode")
            }
            Self::Filesystem { path, .. } => {
                write!(formatter, "cannot read or write {}", path.display())
            }
            Self::ForeignRecord { path } => write!(
                formatter,
                "{} is not a recorded certificate chain",
                path.display()
            ),
            Self::MalformedChainFile { path, .. } => write!(
                formatter,
                "the recorded chain {} does not parse",
                path.display()
            ),
            Self::CrlUnavailable { subject, .. } => write!(
                formatter,
                "no distribution point of {subject:?} yielded a CRL"
            ),
            Self::MalformedCrl { .. } => {
                write!(formatter, "a fetched CRL does not parse")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedToken { source }
            | Self::MalformedDistributionPoints { source }
            | Self::Encoding { source }
            | Self::MalformedChainFile { source, .. }
            | Self::CrlUnavailable { source, .. }
            | Self::MalformedCrl { source } => Some(source.as_ref()),
            Self::Filesystem { source, .. } => Some(source),
            Self::NotSignedData { .. }
            | Self::WrongSignerCount { .. }
            | Self::UnkeyableSigner
            | Self::MissingCertificates
            | Self::ForeignCertificateForm
            | Self::UnusableDistributionPoints { .. }
            | Self::ForeignRecord { .. } => None,
        }
    }
}

fn issuer_key(issuer: &Name) -> Result<String, Error> {
    let issuer_der = issuer.to_der().map_err(|source| Error::Encoding {
        source: Box::new(source),
    })?;
    Ok(hex::encode(hex::LOWERCASE, &Sha256::digest(issuer_der)))
}

/// Materializes the directories the records live in. The very first
/// record meets a worktree where `ltv/` does not exist yet; that
/// scaffolding is this module's own business — never the stamping
/// flow's — and runs as a named step at each recording entry point
/// rather than hiding inside the write helper.
fn materialize_record_directories(worktree: &Path) -> Result<(), Error> {
    for directory_path in [LTV_CERTS_PATH, LTV_CRLS_PATH] {
        let directory = worktree.join(directory_path);
        fs::create_dir_all(&directory).map_err(|source| {
            Error::Filesystem {
                path: directory.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

fn write_text_file(file_path: &Path, text: &str) -> Result<(), Error> {
    fs::write(file_path, text).map_err(|source| Error::Filesystem {
        path: file_path.to_path_buf(),
        source,
    })
}

/// The URIs a certificate's CRL distribution points advertise, or
/// `None` when the certificate carries no such extension at all.
///
/// The `https://` requirement of site URLs does not extend here: a
/// distribution point comes from a certificate, its usual scheme is
/// plain `http://`, and the CRL it serves is signed — transport
/// integrity adds nothing to it. Forms other than a full-name URI
/// (LDAP and directory names, relative-to-issuer points) are passed
/// over when a usable URI stands beside them, as it commonly does;
/// an extension yielding no usable URI at all is the caller's cue to
/// refuse rather than read the certificate as advertising nothing.
fn distribution_uris(
    certificate: &Certificate,
) -> Result<Option<Vec<String>>, Error> {
    let Some(extensions) = &certificate.tbs_certificate.extensions else {
        return Ok(None);
    };
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.extn_id == CrlDistributionPoints::OID)
    else {
        return Ok(None);
    };
    let points =
        CrlDistributionPoints::from_der(extension.extn_value.as_bytes())
            .map_err(|source| Error::MalformedDistributionPoints {
                source: Box::new(source),
            })?;
    let mut uris = Vec::new();
    for point in points.0 {
        let Some(DistributionPointName::FullName(names)) =
            point.distribution_point
        else {
            continue;
        };
        for name in names {
            if let GeneralName::UniformResourceIdentifier(uri) = name {
                uris.push(uri.to_string());
            }
        }
    }
    Ok(Some(uris))
}

/// Normalizes a fetched CRL to its DER bytes: a distribution point
/// may serve DER or PEM (freeTSA publishes PEM), and both spell the
/// same signed structure.
fn crl_der_of(fetched_bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    let malformed = |source: FailureCause| Error::MalformedCrl { source };
    if !fetched_bytes.starts_with(b"-----BEGIN") {
        return Ok(fetched_bytes);
    }
    let (label, der_bytes) = pem_rfc7468::decode_vec(&fetched_bytes)
        .map_err(|source| malformed(Box::new(source)))?;
    if label != CRL_PEM_LABEL {
        return Err(malformed(
            format!("PEM label {label:?} is not {CRL_PEM_LABEL:?}").into(),
        ));
    }
    Ok(der_bytes)
}

/// One fetched CRL: its normalized DER and the record key derived
/// from its own issuer name.
#[derive(Debug)]
struct FetchedCrl {
    issuer_key: String,
    der_bytes: Vec<u8>,
}

/// One CRL snapshot recorded in the working tree, reported so the
/// stamping flow can mirror step 2's refresh into the tree being
/// stamped — the manifest must cover it.
#[derive(Debug)]
pub struct RecordedCrl {
    /// Repository-relative path of the snapshot file.
    pub repository_path: String,
    /// The recorded PEM bytes, exactly as written.
    pub pem_bytes: Vec<u8>,
    /// The CRL itself, for a verification basis.
    pub der_bytes: Vec<u8>,
}

fn fetch_crl(certificate: &Certificate) -> Result<Option<FetchedCrl>, Error> {
    // A certificate with no distribution point extension advertises
    // no CRL to fetch; whether that leaves a token verifiable is
    // pre-seal verification's question, not the collector's.
    let Some(uris) = distribution_uris(certificate)? else {
        return Ok(None);
    };
    if uris.is_empty() {
        return Err(Error::UnusableDistributionPoints {
            subject: certificate.tbs_certificate.subject.to_string(),
        });
    }
    let mut maybe_last_failure: Option<FailureCause> = None;
    for uri in &uris {
        match transport::fetch(uri) {
            Ok(fetched_bytes) => {
                let der_bytes = crl_der_of(fetched_bytes)?;
                let crl = CertificateList::from_der(&der_bytes).map_err(
                    |source| Error::MalformedCrl {
                        source: Box::new(source),
                    },
                )?;
                return Ok(Some(FetchedCrl {
                    issuer_key: issuer_key(&crl.tbs_cert_list.issuer)?,
                    der_bytes,
                }));
            }
            Err(source) => maybe_last_failure = Some(source),
        }
    }
    Err(Error::CrlUnavailable {
        subject: certificate.tbs_certificate.subject.to_string(),
        source: maybe_last_failure
            .expect("a nonempty URI list that never returned has failed"),
    })
}

/// Fetches the CRLs a chain advertises, one per CRL issuer, without
/// touching the file system.
fn fetch_chain_crls(chain: &[Certificate]) -> Result<Vec<FetchedCrl>, Error> {
    let mut fetched_crls: Vec<FetchedCrl> = Vec::new();
    for certificate in chain {
        let Some(fetched) = fetch_crl(certificate)? else {
            continue;
        };
        if fetched_crls
            .iter()
            .any(|held| held.issuer_key == fetched.issuer_key)
        {
            continue;
        }
        fetched_crls.push(fetched);
    }
    Ok(fetched_crls)
}

/// Records the CRLs of one chain under `ltv/crls/`, reporting what
/// was written. One snapshot per CRL issuer; the working tree holds
/// only the latest (§3).
fn record_chain_crls(
    worktree: &Path,
    fetched_crls: &[FetchedCrl],
) -> Result<Vec<RecordedCrl>, Error> {
    let mut recorded: Vec<RecordedCrl> = Vec::new();
    for fetched in fetched_crls {
        let repository_path =
            format!("{LTV_CRLS_PATH}/{}{CRL_FILE_SUFFIX}", fetched.issuer_key);
        let pem_text = pem_rfc7468::encode_string(
            CRL_PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            &fetched.der_bytes,
        )
        .map_err(|source| Error::Encoding {
            source: Box::new(source),
        })?;
        write_text_file(&worktree.join(&repository_path), &pem_text)?;
        recorded.push(RecordedCrl {
            repository_path,
            pem_bytes: pem_text.into_bytes(),
            der_bytes: fetched.der_bytes.clone(),
        });
    }
    Ok(recorded)
}

/// The token's embedded chain and the issuer name its signer is
/// identified by, which keys the chain record.
fn token_chain(token_bytes: &[u8]) -> Result<(Name, Vec<Certificate>), Error> {
    let malformed = |source: FailureCause| Error::MalformedToken { source };
    let content = ContentInfo::from_der(token_bytes)
        .map_err(|source| malformed(Box::new(source)))?;
    if content.content_type != ID_SIGNED_DATA {
        return Err(Error::NotSignedData {
            content_type: content.content_type.to_string(),
        });
    }
    let signed: SignedData = content
        .content
        .decode_as()
        .map_err(|source| malformed(Box::new(source)))?;
    let signer_count = signed.signer_infos.0.len();
    if signer_count != 1 {
        return Err(Error::WrongSignerCount {
            count: signer_count,
        });
    }
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .expect("one signer info was counted");
    let SignerIdentifier::IssuerAndSerialNumber(issuer_serial) = &signer.sid
    else {
        return Err(Error::UnkeyableSigner);
    };
    let mut chain = Vec::new();
    let embedded = signed
        .certificates
        .as_ref()
        .ok_or(Error::MissingCertificates)?;
    for choice in embedded.0.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            return Err(Error::ForeignCertificateForm);
        };
        chain.push(certificate.clone());
    }
    if chain.is_empty() {
        return Err(Error::MissingCertificates);
    }
    Ok((issuer_serial.issuer.clone(), chain))
}

/// Trust material harvested from one freshly received token, held in
/// memory until that token passes pre-seal verification: material
/// from a token that never verifies must not settle on disk, where
/// [`refresh`] would keep renewing it on every later stamp.
#[derive(Debug)]
pub struct Harvest {
    chain_repository_path: String,
    chain_pem_text: String,
    fetched_crls: Vec<FetchedCrl>,
}

impl Harvest {
    /// The fetched CRLs, DER, for the harvested token's own
    /// verification basis.
    pub fn crl_ders(&self) -> Vec<Vec<u8>> {
        self.fetched_crls
            .iter()
            .map(|fetched| fetched.der_bytes.clone())
            .collect()
    }
}

/// Harvests the chain a freshly received token carries and fetches
/// the CRL snapshots covering it, touching no files: what settles on
/// disk is [`record`]'s decision, made after the token verified.
pub fn harvest(token_bytes: &[u8]) -> Result<Harvest, Error> {
    let (signer_issuer, chain) = token_chain(token_bytes)?;
    let mut chain_pem_text = String::new();
    for certificate in &chain {
        let block = certificate.to_pem(pem_rfc7468::LineEnding::LF).map_err(
            |source| Error::Encoding {
                source: Box::new(source),
            },
        )?;
        chain_pem_text.push_str(&block);
    }
    Ok(Harvest {
        chain_repository_path: format!(
            "{LTV_CERTS_PATH}/{}{CHAIN_FILE_SUFFIX}",
            issuer_key(&signer_issuer)?
        ),
        chain_pem_text,
        fetched_crls: fetch_chain_crls(&chain)?,
    })
}

/// Records one verified token's harvest in the working tree, where
/// the following stamp seals it (§5).
pub fn record(worktree: &Path, harvest: &Harvest) -> Result<(), Error> {
    materialize_record_directories(worktree)?;
    write_text_file(
        &worktree.join(&harvest.chain_repository_path),
        &harvest.chain_pem_text,
    )?;
    record_chain_crls(worktree, &harvest.fetched_crls)?;
    Ok(())
}

/// Refreshes the CRL snapshots for every chain already on record
/// (§5 step 2). Runs before the manifest is fixed and reports what
/// it wrote, so the stamping flow can mirror the snapshots into the
/// tree being stamped — the covering stamp must seal revocation data
/// of the same moment as its tokens.
pub fn refresh(worktree: &Path) -> Result<Vec<RecordedCrl>, Error> {
    let certs_directory = worktree.join(LTV_CERTS_PATH);
    let entries = match fs::read_dir(&certs_directory) {
        Ok(entries) => entries,
        // No records yet — the repository has not deposited a chain.
        Err(source) if source.kind() == ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(source) => {
            return Err(Error::Filesystem {
                path: certs_directory,
                source,
            });
        }
    };
    materialize_record_directories(worktree)?;
    let mut refreshed = Vec::new();
    for maybe_entry in entries {
        let entry = maybe_entry.map_err(|source| Error::Filesystem {
            path: certs_directory.clone(),
            source,
        })?;
        let file_path = entry.path();
        let is_chain_record = file_path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .is_some_and(|file_name| file_name.ends_with(CHAIN_FILE_SUFFIX));
        if !is_chain_record {
            return Err(Error::ForeignRecord { path: file_path });
        }
        let pem_bytes =
            fs::read(&file_path).map_err(|source| Error::Filesystem {
                path: file_path.clone(),
                source,
            })?;
        let chain =
            Certificate::load_pem_chain(&pem_bytes).map_err(|source| {
                Error::MalformedChainFile {
                    path: file_path.clone(),
                    source: Box::new(source),
                }
            })?;
        if chain.is_empty() {
            return Err(Error::MalformedChainFile {
                path: file_path,
                source: "the file holds no certificate blocks".into(),
            });
        }
        let fetched_crls = fetch_chain_crls(&chain)?;
        refreshed.extend(record_chain_crls(worktree, &fetched_crls)?);
    }
    Ok(refreshed)
}

#[cfg(test)]
use super::{test_http, test_pki};

#[cfg(test)]
mod tests {
    use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
    use der::asn1::OctetString;
    use x509_cert::ext::pkix::crl::dp::DistributionPoint;

    use super::test_http::{bind_one_shot, http_response};
    use super::test_pki;

    use super::*;

    const PAYLOAD: &[u8] = b"tydence-manifest/v1\n";

    fn write_fixture_record(file_path: &Path, text: &str) {
        fs::create_dir_all(
            file_path
                .parent()
                .expect("the fixture path has a directory"),
        )
        .expect("the fixture directory creates");
        fs::write(file_path, text).expect("the fixture writes");
    }

    fn token_of(authority: &test_pki::Authority) -> Vec<u8> {
        test_pki::encode_token(
            &test_pki::standard_token_parts(PAYLOAD, authority),
            &authority.tsa_key,
        )
    }

    // Computed independently of the production issuer_key helper, so
    // a keying bug cannot cancel out on both sides of an assertion.
    fn expected_root_key() -> String {
        let issuer_der =
            test_pki::der_of(&test_pki::parse_name(test_pki::ROOT_NAME));
        Sha256::digest(issuer_der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// A syntactically valid SignedData token with the given signers
    /// and certificate set, for the defect shapes [`token_of`]
    /// cannot spell.
    fn hollow_token(
        signer_infos: der::asn1::SetOfVec<cms::signed_data::SignerInfo>,
        certificates: Option<cms::signed_data::CertificateSet>,
    ) -> Vec<u8> {
        let signed_data = SignedData {
            version: cms::content_info::CmsVersion::V3,
            digest_algorithms: der::asn1::SetOfVec::new(),
            encap_content_info: cms::signed_data::EncapsulatedContentInfo {
                econtent_type: ID_SIGNED_DATA,
                econtent: None,
            },
            certificates,
            crls: None,
            signer_infos: cms::signed_data::SignerInfos(signer_infos),
        };
        test_pki::der_of(&ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: der::Any::encode_from(&signed_data)
                .expect("the fixture SignedData wraps"),
        })
    }

    /// A minimal signer whose identifier carries the fixture root's
    /// issuer name, so `token_chain` gets past the keying check.
    fn keyable_signer(
        authority: &test_pki::Authority,
    ) -> cms::signed_data::SignerInfo {
        cms::signed_data::SignerInfo {
            version: cms::content_info::CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(
                cms::cert::IssuerAndSerialNumber {
                    issuer: authority
                        .tsa_certificate
                        .tbs_certificate
                        .issuer
                        .clone(),
                    serial_number: authority
                        .tsa_certificate
                        .tbs_certificate
                        .serial_number
                        .clone(),
                },
            ),
            digest_alg: test_pki::sha256_identifier(),
            signed_attrs: None,
            signature_algorithm: test_pki::sha256_identifier(),
            signature: OctetString::new(vec![0xCD; 8])
                .expect("the placeholder signature encodes"),
            unsigned_attrs: None,
        }
    }

    #[test]
    fn a_recorded_harvest_settles_the_chain_and_its_crls() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        let crl_der = test_pki::der_of(&test_pki::standard_crl(&authority));
        let _requests = server.respond_with(http_response(
            "200 OK",
            "application/pkix-crl",
            &crl_der,
        ));
        let harvested =
            harvest(&token_of(&authority)).expect("the harvest succeeds");
        assert_eq!(harvested.crl_ders(), vec![crl_der.clone()]);
        let worktree = tempfile::tempdir().expect("tempdir");
        record(worktree.path(), &harvested).expect("the record succeeds");
        let chain_file = worktree
            .path()
            .join(LTV_CERTS_PATH)
            .join(format!("{}{CHAIN_FILE_SUFFIX}", expected_root_key()));
        let chain = Certificate::load_pem_chain(
            &fs::read(&chain_file).expect("the chain file exists"),
        )
        .expect("the chain file parses");
        // A CMS certificate set is a DER SET OF: its order is byte
        // canonical, not insertion order, so the file is checked as
        // a set.
        assert_eq!(chain.len(), 2);
        assert!(chain.contains(&authority.tsa_certificate));
        assert!(chain.contains(&authority.root_certificate));
        let crl_file = worktree
            .path()
            .join(LTV_CRLS_PATH)
            .join(format!("{}{CRL_FILE_SUFFIX}", expected_root_key()));
        let crl_pem = fs::read(&crl_file).expect("the CRL file exists");
        // The framing is asserted against the literal RFC 7468
        // encapsulation boundary, not the constant the writer used,
        // so a wrong label cannot cancel out on both sides.
        let crl_text =
            String::from_utf8(crl_pem.clone()).expect("the file is text");
        assert!(crl_text.starts_with("-----BEGIN X509 CRL-----\n"));
        assert!(crl_text.ends_with("-----END X509 CRL-----\n"));
        let (label, recorded_der) =
            pem_rfc7468::decode_vec(&crl_pem).expect("the CRL file is PEM");
        assert_eq!(label, CRL_PEM_LABEL);
        assert_eq!(recorded_der, crl_der);
    }

    #[test]
    fn a_refresh_renews_the_crls_of_recorded_chains() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        let crl_der = test_pki::der_of(&test_pki::standard_crl(&authority));
        let _requests = server.respond_with(http_response(
            "200 OK",
            "application/pkix-crl",
            &crl_der,
        ));
        let worktree = tempfile::tempdir().expect("tempdir");
        let mut chain_text = String::new();
        for certificate in
            [&authority.tsa_certificate, &authority.root_certificate]
        {
            chain_text.push_str(
                &certificate
                    .to_pem(pem_rfc7468::LineEnding::LF)
                    .expect("the fixture certificate encodes"),
            );
        }
        let chain_file = worktree
            .path()
            .join(LTV_CERTS_PATH)
            .join(format!("{}{CHAIN_FILE_SUFFIX}", expected_root_key()));
        write_fixture_record(&chain_file, &chain_text);
        refresh(worktree.path()).expect("the refresh succeeds");
        let crl_file = worktree
            .path()
            .join(LTV_CRLS_PATH)
            .join(format!("{}{CRL_FILE_SUFFIX}", expected_root_key()));
        let crl_pem = fs::read(&crl_file).expect("the CRL file exists");
        let (_, recorded_der) =
            pem_rfc7468::decode_vec(&crl_pem).expect("the CRL file is PEM");
        assert_eq!(recorded_der, crl_der);
    }

    #[test]
    fn a_refresh_without_records_is_a_quiet_success() {
        let worktree = tempfile::tempdir().expect("tempdir");
        refresh(worktree.path()).expect("nothing on record refreshes");
    }

    #[test]
    fn a_pem_encoded_crl_is_accepted() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        let crl_der = test_pki::der_of(&test_pki::standard_crl(&authority));
        let crl_pem = pem_rfc7468::encode_string(
            CRL_PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            &crl_der,
        )
        .expect("the fixture CRL encodes");
        let _requests = server.respond_with(http_response(
            "200 OK",
            "application/x-pem-file",
            crl_pem.as_bytes(),
        ));
        let harvested = harvest(&token_of(&authority))
            .expect("the PEM-served CRL harvests");
        assert_eq!(harvested.crl_ders(), vec![crl_der]);
    }

    #[test]
    fn an_unreachable_distribution_point_fails() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        // The port closes before any fetch happens.
        drop(server);
        let verdict = harvest(&token_of(&authority));
        assert!(matches!(verdict, Err(Error::CrlUnavailable { .. })));
    }

    #[test]
    fn a_crl_that_does_not_parse_fails() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        let _requests = server.respond_with(http_response(
            "200 OK",
            "application/pkix-crl",
            b"not a crl",
        ));
        let verdict = harvest(&token_of(&authority));
        assert!(matches!(verdict, Err(Error::MalformedCrl { .. })));
    }

    #[test]
    fn a_malformed_distribution_points_extension_fails() {
        let mut extensions = test_pki::tsa_extensions();
        extensions.push(x509_cert::ext::Extension {
            extn_id: CrlDistributionPoints::OID,
            critical: false,
            extn_value: OctetString::new(b"not distribution points".to_vec())
                .expect("the garbage value encodes"),
        });
        let authority = test_pki::authority_with_tsa_extensions(extensions);
        let verdict = harvest(&token_of(&authority));
        assert!(matches!(
            verdict,
            Err(Error::MalformedDistributionPoints { .. })
        ));
    }

    #[test]
    fn a_pem_crl_under_a_foreign_label_fails() {
        let server = bind_one_shot();
        let authority = test_pki::authority_with_crl_distribution(&server.url);
        let crl_der = test_pki::der_of(&test_pki::standard_crl(&authority));
        // Right bytes, wrong encapsulation label: whatever this is,
        // it does not declare itself a CRL.
        let mislabeled_pem = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &crl_der,
        )
        .expect("the fixture encodes");
        let _requests = server.respond_with(http_response(
            "200 OK",
            "application/x-pem-file",
            mislabeled_pem.as_bytes(),
        ));
        let verdict = harvest(&token_of(&authority));
        assert!(matches!(verdict, Err(Error::MalformedCrl { .. })));
    }

    #[test]
    fn a_distribution_point_without_a_usable_uri_fails() {
        // The extension is present, but its one point carries no
        // full-name URI: revocation data exists somewhere, and
        // reading that as "nothing advertised" would silently skip
        // it.
        let points = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: None,
            reasons: None,
            crl_issuer: None,
        }]);
        let mut extensions = test_pki::tsa_extensions();
        extensions.push(test_pki::extension_of(&points, false));
        let authority = test_pki::authority_with_tsa_extensions(extensions);
        let verdict = harvest(&token_of(&authority));
        assert!(matches!(
            verdict,
            Err(Error::UnusableDistributionPoints { .. })
        ));
    }

    #[test]
    fn a_chain_without_distribution_points_harvests_no_crls() {
        let authority = test_pki::standard_authority();
        let harvested = harvest(&token_of(&authority))
            .expect("a chain advertising no CRLs still harvests");
        assert!(harvested.crl_ders().is_empty());
        let worktree = tempfile::tempdir().expect("tempdir");
        record(worktree.path(), &harvested).expect("the record succeeds");
        let chain_file = worktree
            .path()
            .join(LTV_CERTS_PATH)
            .join(format!("{}{CHAIN_FILE_SUFFIX}", expected_root_key()));
        assert!(chain_file.exists());
    }

    #[test]
    fn a_token_identifying_its_signer_by_key_id_cannot_be_keyed() {
        let authority = test_pki::standard_authority();
        let mut parts = test_pki::standard_token_parts(PAYLOAD, &authority);
        parts.sid =
            SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
                OctetString::new(vec![0xAB; 20]).expect("the key id encodes"),
            ));
        let token = test_pki::encode_token(&parts, &authority.tsa_key);
        let verdict = harvest(&token);
        assert!(matches!(verdict, Err(Error::UnkeyableSigner)));
    }

    #[test]
    fn a_garbage_token_fails_to_harvest() {
        let verdict = harvest(b"not a token");
        assert!(matches!(verdict, Err(Error::MalformedToken { .. })));
    }

    #[test]
    fn a_token_that_is_not_signed_data_fails_to_harvest() {
        let foreign_content = test_pki::der_of(&ContentInfo {
            // id-data (RFC 5652 §4), a content type a token never has
            content_type: der::oid::ObjectIdentifier::new_unwrap(
                "1.2.840.113549.1.7.1",
            ),
            content: der::Any::null(),
        });
        let verdict = harvest(&foreign_content);
        assert!(matches!(verdict, Err(Error::NotSignedData { .. })));
    }

    #[test]
    fn a_token_without_signers_fails_to_harvest() {
        let token = hollow_token(der::asn1::SetOfVec::new(), None);
        let verdict = harvest(&token);
        assert!(matches!(verdict, Err(Error::WrongSignerCount { count: 0 })));
    }

    #[test]
    fn a_token_without_certificates_fails_to_harvest() {
        let authority = test_pki::standard_authority();
        let mut signers = der::asn1::SetOfVec::new();
        signers
            .insert(keyable_signer(&authority))
            .expect("the signer inserts");
        let token = hollow_token(signers, None);
        let verdict = harvest(&token);
        assert!(matches!(verdict, Err(Error::MissingCertificates)));
    }

    #[test]
    fn a_foreign_certificate_form_fails_to_deposit() {
        let authority = test_pki::standard_authority();
        let mut signers = der::asn1::SetOfVec::new();
        signers
            .insert(keyable_signer(&authority))
            .expect("the signer inserts");
        let mut choices = der::asn1::SetOfVec::new();
        choices
            .insert(CertificateChoices::Other(
                cms::cert::OtherCertificateFormat {
                    other_cert_format: der::oid::ObjectIdentifier::new_unwrap(
                        "1.3.6.1.4.1.99999.1",
                    ),
                    other_cert: der::Any::null(),
                },
            ))
            .expect("the foreign choice inserts");
        let token = hollow_token(
            signers,
            Some(cms::signed_data::CertificateSet(choices)),
        );
        let verdict = harvest(&token);
        assert!(matches!(verdict, Err(Error::ForeignCertificateForm)));
    }

    #[test]
    fn a_chain_record_that_does_not_parse_fails_the_refresh() {
        let worktree = tempfile::tempdir().expect("tempdir");
        let chain_file = worktree
            .path()
            .join(LTV_CERTS_PATH)
            .join(format!("{}{CHAIN_FILE_SUFFIX}", expected_root_key()));
        write_fixture_record(&chain_file, "not a certificate chain");
        let verdict = refresh(worktree.path());
        assert!(matches!(verdict, Err(Error::MalformedChainFile { .. })));
    }

    #[test]
    fn a_foreign_file_under_the_chain_records_fails_the_refresh() {
        let worktree = tempfile::tempdir().expect("tempdir");
        let foreign_file =
            worktree.path().join(LTV_CERTS_PATH).join("notes.txt");
        write_fixture_record(&foreign_file, "not a chain");
        let verdict = refresh(worktree.path());
        assert!(matches!(verdict, Err(Error::ForeignRecord { .. })));
    }
}
