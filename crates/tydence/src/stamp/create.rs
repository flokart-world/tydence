//! The whole stamping flow (stamping specification §5), one entry
//! point walking every step over a repository: refresh the recorded
//! CRLs and mirror them into the tree being stamped, read the policy
//! from that very tree, fix the manifest over its snapshot and the
//! bound predecessors, acquire one fully verified token per selected
//! site over live HTTPS — depositing newly learned trust material on
//! the way — and seal everything into the stamp commit.
//!
//! The configuration is read from the content being stamped, never
//! from anywhere else: the sealed policy is exactly the policy that
//! was used.

use gix::objs::tree::EntryKind;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;

use super::acquire::{self, AcquireInputs};
use super::bind;
use super::config::{self, Config};
use super::hex;
use super::layout::CONFIG_PATH;
use super::ltv;
use super::manifest::{
    Manifest, PayloadHashes, UnprintableField, hash_payload,
};
use super::seal::{self, SealInputs};
use super::snapshot;
use super::transport::HttpsTransport;
use super::tsp::{Rfc3161Anchor, StampEnvironment, TimestampAnchor};
use super::verify::TrustData;

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

/// The live ambient inputs (requirement N3): nonce bytes from the
/// operating system's RNG, the moment from the system clock. Tests
/// substitute fixed values through the same [`StampEnvironment`]
/// boundary.
#[derive(Clone, Copy, Debug)]
pub struct OsEnvironment;

impl StampEnvironment for OsEnvironment {
    fn draw_nonce(&mut self) -> [u8; 8] {
        let mut nonce_bytes = [0u8; 8];
        // Refusing to stamp is the only right answer to an OS RNG
        // that cannot produce eight bytes.
        getrandom::fill(&mut nonce_bytes).expect("the OS RNG answers");
        nonce_bytes
    }

    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Debug)]
pub enum Error {
    /// The repository has no working tree to keep LTV deposits in.
    BareRepository,
    /// Git objects the flow needs could not be read or written.
    ObjectAccess {
        source: FailureCause,
    },
    /// The content being stamped carries no readable
    /// `.tydence/config`, so no profile can select any site.
    MissingConfig,
    /// `.tydence/config` in the content being stamped is not a
    /// regular UTF-8 text file.
    UnreadableConfig {
        source: FailureCause,
    },
    Config(config::Error),
    Ltv(ltv::Error),
    Snapshot(snapshot::Error),
    Bind(bind::Error),
    /// A manifest field cannot be spelled — a site name a bound
    /// stamp carries is not a printable bare token, say.
    Unprintable(UnprintableField),
    Acquire(acquire::Error),
    Seal(seal::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BareRepository => write!(
                formatter,
                "the repository has no working tree to record LTV \
                 material in"
            ),
            Self::ObjectAccess { .. } => {
                write!(formatter, "cannot read or write git objects")
            }
            Self::MissingConfig => write!(
                formatter,
                "the content being stamped carries no {CONFIG_PATH}"
            ),
            Self::UnreadableConfig { .. } => write!(
                formatter,
                "{CONFIG_PATH} in the content being stamped is not a \
                 regular UTF-8 text file"
            ),
            Self::Config(cause) => {
                write!(formatter, "the configuration does not parse: {cause}")
            }
            Self::Ltv(cause) => {
                write!(formatter, "the LTV material did not settle: {cause}")
            }
            Self::Snapshot(cause) => {
                write!(formatter, "the snapshot does not enumerate: {cause}")
            }
            Self::Bind(cause) => {
                write!(formatter, "the binding set does not build: {cause}")
            }
            Self::Unprintable(cause) => {
                write!(formatter, "the manifest cannot be spelled: {cause}")
            }
            Self::Acquire(cause) => {
                write!(formatter, "token acquisition failed: {cause}")
            }
            Self::Seal(cause) => {
                write!(formatter, "the stamp did not seal: {cause}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectAccess { source }
            | Self::UnreadableConfig { source } => Some(source.as_ref()),
            Self::Config(cause) => Some(cause),
            Self::Ltv(cause) => Some(cause),
            Self::Snapshot(cause) => Some(cause),
            Self::Bind(cause) => Some(cause),
            Self::Unprintable(cause) => Some(cause),
            Self::Acquire(cause) => Some(cause),
            Self::Seal(cause) => Some(cause),
            Self::BareRepository | Self::MissingConfig => None,
        }
    }
}

/// Everything one stamp consumes beyond the repository itself. The
/// git-facing fields mirror [`SealInputs`]; the trust anchors are
/// the external supply pre-seal verification judges against — never
/// taken from the repository, which must not certify itself.
#[derive(Debug)]
pub struct CreateInputs<'a> {
    /// The tree holding the fixed content to stamp (§5 step 1),
    /// before the CRL refresh of step 2 is mirrored in.
    pub base_tree_id: gix::ObjectId,
    /// The profile to stamp with, named explicitly (configuration
    /// manual §3.2).
    pub profile_name: &'a str,
    /// Trust anchor certificates, DER.
    pub anchor_certificates: &'a [Vec<u8>],
    pub parent_ids: &'a [gix::ObjectId],
    pub message: &'a str,
    pub author: &'a gix::actor::Signature,
    pub committer: &'a gix::actor::Signature,
    /// The full reference name to move, `refs/heads/...`.
    pub reference_name: &'a str,
    /// What the reference must hold for the seal to be allowed.
    pub expected: gix::refs::transaction::PreviousValue,
}

/// A sealed stamp: the commit that now carries it, the double hash
/// of its manifest, and the tolerated per-site failures that must
/// still reach the user's eyes.
#[derive(Debug)]
pub struct CreatedStamp {
    pub commit_id: gix::ObjectId,
    pub manifest_hashes: PayloadHashes,
    pub warnings: Vec<acquire::SiteFailure>,
}

/// Appends the `Tydence-Stamp` trailers to the commit message: one
/// line per hash family, spelled exactly like a manifest payload
/// field, so a later manifest's `past-manifest` line can be matched
/// against plain `git log` output by eye. Convenience only — no
/// verification reads commit messages.
fn message_with_trailers(message: &str, hashes: &PayloadHashes) -> String {
    format!(
        "{}\n\nTydence-Stamp: sha256:{}\nTydence-Stamp: sha3-256:{}\n",
        message.trim_end(),
        hex::encode(hex::LOWERCASE, &hashes.sha256),
        hex::encode(hex::LOWERCASE, &hashes.sha3_256),
    )
}

/// Mirrors the working tree's LTV records onto the tree being
/// stamped, so the manifest covers them. This is the step that
/// seals the deposit a previous stamp left behind (§5): a record
/// the tree already seals mirrors to the identical blob and changes
/// nothing, so only deposits make a difference.
fn apply_ltv_records(
    repository: &gix::Repository,
    base_tree_id: gix::ObjectId,
    records: &ltv::Records,
) -> Result<gix::ObjectId, Error> {
    if records.chains.is_empty() && records.crls.is_empty() {
        return Ok(base_tree_id);
    }
    let object_access = |source: FailureCause| Error::ObjectAccess { source };
    let mut editor = repository
        .edit_tree(base_tree_id)
        .map_err(|source| object_access(Box::new(source)))?;
    let files = records
        .chains
        .iter()
        .map(|chain| (&chain.repository_path, &chain.pem_bytes))
        .chain(
            records
                .crls
                .iter()
                .map(|crl| (&crl.repository_path, &crl.pem_bytes)),
        );
    for (repository_path, pem_bytes) in files {
        let blob = repository
            .write_blob(pem_bytes)
            .map_err(|source| object_access(Box::new(source)))?
            .detach();
        editor
            .upsert(repository_path, EntryKind::Blob, blob)
            .map_err(|source| object_access(Box::new(source)))?;
    }
    editor
        .write()
        .map(|tree_id| tree_id.detach())
        .map_err(|source| object_access(Box::new(source)))
}

/// Reads the stamping policy out of the content being stamped.
fn read_config(
    repository: &gix::Repository,
    content_tree_id: gix::ObjectId,
) -> Result<Config, Error> {
    let object_access = |source: FailureCause| Error::ObjectAccess { source };
    let tree = repository
        .find_tree(content_tree_id)
        .map_err(|source| object_access(Box::new(source)))?;
    let entry = tree
        .lookup_entry_by_path(CONFIG_PATH)
        .map_err(|source| object_access(Box::new(source)))?
        .ok_or(Error::MissingConfig)?;
    if !entry.mode().is_blob() {
        return Err(Error::UnreadableConfig {
            source: "the path names no regular file".into(),
        });
    }
    let blob = repository
        .find_blob(entry.object_id())
        .map_err(|source| object_access(Box::new(source)))?;
    let config_text = std::str::from_utf8(&blob.data).map_err(|source| {
        Error::UnreadableConfig {
            source: Box::new(source),
        }
    })?;
    config::parse(config_text).map_err(Error::Config)
}

/// The live per-site wiring: HTTPS transport to the site's URL,
/// nonce and clock from the operating system. Everything ambient a
/// stamp touches passes through the `make_anchor` boundary of
/// [`run`], so deterministic tests substitute the whole anchor.
pub fn live_anchor(
    site: &config::Site,
) -> Rfc3161Anchor<HttpsTransport, OsEnvironment> {
    Rfc3161Anchor {
        transport: HttpsTransport::new(&site.url),
        environment: OsEnvironment,
        imprint_algorithm: site.imprint_algorithm,
    }
}

/// Creates one stamp commit (stamping specification §5, steps 2–7;
/// step 1's fixed content arrives as `inputs.base_tree_id`). Live
/// use passes `|_, site| live_anchor(site)` as `make_anchor`.
/// Returns the sealed commit and the tolerated site failures.
pub fn run<MakeAnchor, Anchor>(
    repository: &gix::Repository,
    inputs: &CreateInputs<'_>,
    make_anchor: MakeAnchor,
) -> Result<CreatedStamp, Error>
where
    MakeAnchor: FnMut(&str, &config::Site) -> Anchor,
    Anchor: TimestampAnchor,
    Anchor::Error: Send + Sync + 'static,
{
    let worktree: PathBuf = repository
        .workdir()
        .ok_or(Error::BareRepository)?
        .to_owned();
    // §5 step 2.
    let records = ltv::refresh(&worktree).map_err(Error::Ltv)?;
    let content_tree_id =
        apply_ltv_records(repository, inputs.base_tree_id, &records)?;
    let config = read_config(repository, content_tree_id)?;
    // §5 step 3 — the manifest is a pure function of the snapshot
    // and the binding set; serializing it fixes the imprint.
    let entries =
        snapshot::run(repository, content_tree_id).map_err(Error::Snapshot)?;
    let binding_groups =
        bind::run(repository, inputs.parent_ids).map_err(Error::Bind)?;
    let manifest = Manifest {
        parents: inputs
            .parent_ids
            .iter()
            .map(|parent| parent.to_string())
            .collect(),
        binding_groups,
        entries,
    };
    let manifest_text = manifest.serialize().map_err(Error::Unprintable)?;
    let manifest_hashes = hash_payload(manifest_text.as_bytes());
    // §5 steps 4–5 — one fully verified token per selected site. The
    // refreshed snapshots serve as the base CRLs; each token's own
    // chain material arrives through the deposit supplement.
    let refreshed_crls: Vec<Vec<u8>> = records
        .crls
        .into_iter()
        .map(|record| record.der_bytes)
        .collect();
    // Each token's chain material is harvested in memory only; it
    // settles on disk below, and only for tokens that verified —
    // material from a refused token must not become a record that
    // every later refresh keeps renewing.
    let mut harvests: HashMap<String, ltv::Harvest> = HashMap::new();
    let acquisition = acquire::run(
        &AcquireInputs {
            config: &config,
            profile_name: inputs.profile_name,
            manifest_bytes: manifest_text.as_bytes(),
            trust: TrustData {
                anchor_certificates: inputs.anchor_certificates,
                companion_certificates: &[],
                crls: &refreshed_crls,
            },
        },
        make_anchor,
        |site_name, token_bytes| {
            let harvest =
                ltv::harvest(token_bytes).map_err(|harvest_error| {
                    Box::new(harvest_error) as FailureCause
                })?;
            let crl_ders = harvest.crl_ders();
            harvests.insert(site_name.to_string(), harvest);
            Ok(crl_ders)
        },
    )
    .map_err(Error::Acquire)?;
    // §5 step 6's deferred deposit, for the verified tokens only.
    for token in &acquisition.tokens {
        let harvest = harvests
            .remove(&token.site_name)
            .expect("every acquired token was supplemented");
        ltv::record(&worktree, &harvest).map_err(Error::Ltv)?;
    }
    // §5 steps 6–7 — seal.
    let sealed_message =
        message_with_trailers(inputs.message, &manifest_hashes);
    let commit_id = seal::run(
        repository,
        &SealInputs {
            base_tree_id: content_tree_id,
            manifest_bytes: manifest_text.as_bytes(),
            tokens: &acquisition.tokens,
            parent_ids: inputs.parent_ids,
            message: &sealed_message,
            author: inputs.author,
            committer: inputs.committer,
            reference_name: inputs.reference_name,
            expected: inputs.expected.clone(),
        },
    )
    .map_err(Error::Seal)?;
    Ok(CreatedStamp {
        commit_id,
        manifest_hashes,
        warnings: acquisition.warnings,
    })
}

#[cfg(test)]
use super::{layout, manifest, test_git, test_stamp, verify};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::layout::{
        LTV_CERTS_PATH, LTV_CRLS_PATH, MANIFEST_PATH, TOKENS_PATH,
    };
    use super::manifest::{AnchorSpec, hash_payload, parse_manifest};
    use super::test_git::{
        blob_bytes_at, commit_id_of, init_repository, run_git,
    };
    use super::test_stamp::{
        Fixture, https_spelling, live_fixture, prepare_repository, stamp_head,
    };
    use super::verify::{SiteToken, StampInputs, verify_stamp};

    use super::*;

    fn entry_paths(manifest_text: &str) -> Vec<Vec<u8>> {
        parse_manifest(manifest_text)
            .expect("the sealed manifest parses")
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect()
    }

    /// What one full verification of a sealed stamp judges against.
    struct Verification<'a> {
        fixture: &'a Fixture,
        bound_stamps: &'a [verify::BoundStamp<'a>],
    }

    fn verified_summary(
        repository_dir: &Path,
        commit_id: gix::ObjectId,
        verification: &Verification<'_>,
    ) -> Result<verify::StampSummary, verify::Error> {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        let tree_id = repository
            .find_commit(commit_id)
            .expect("the stamp exists")
            .tree_id()
            .expect("the stamp has a tree")
            .detach();
        let tree_entries = snapshot::run(&repository, tree_id)
            .expect("the stamp tree enumerates");
        let manifest_bytes =
            blob_bytes_at(repository_dir, commit_id, MANIFEST_PATH);
        let token_bytes = blob_bytes_at(
            repository_dir,
            commit_id,
            &format!("{TOKENS_PATH}/loop.tsr"),
        );
        let crls = vec![verification.fixture.crl_der.clone()];
        verify_stamp(&StampInputs {
            manifest_bytes: &manifest_bytes,
            tree_entries: &tree_entries,
            tokens: &[SiteToken {
                site: "loop",
                bytes: &token_bytes,
            }],
            bound_stamps: verification.bound_stamps,
            trust: verify::TrustData {
                anchor_certificates: &verification.fixture.anchors,
                companion_certificates: &[],
                crls: &crls,
            },
        })
    }

    #[test]
    fn a_first_stamp_seals_a_verifiable_commit() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let created = stamp_head(repository_dir.path(), &fixture)
            .expect("the first stamp seals");
        assert!(created.warnings.is_empty());
        assert_eq!(
            commit_id_of(repository_dir.path(), "HEAD"),
            created.commit_id
        );
        let manifest_bytes = blob_bytes_at(
            repository_dir.path(),
            created.commit_id,
            MANIFEST_PATH,
        );
        let manifest_text =
            String::from_utf8(manifest_bytes).expect("the manifest is text");
        let manifest =
            parse_manifest(&manifest_text).expect("the manifest parses");
        assert!(manifest.binding_groups.is_empty());
        let paths = entry_paths(&manifest_text);
        assert!(paths.contains(&b"work.txt".to_vec()));
        assert!(paths.contains(&b".tydence/config".to_vec()));
        // The deposit stayed out of this stamp's tree — the working
        // tree holds it for the following stamp to seal.
        assert!(!paths.iter().any(|path| path.starts_with(b".tydence/ltv/")));
        assert!(
            repository_dir
                .path()
                .join(LTV_CERTS_PATH)
                .read_dir()
                .expect("the deposit directory exists")
                .next()
                .is_some()
        );
        // The full verifier accepts the sealed stamp: the flow and
        // the verdict agree end to end.
        let summary = verified_summary(
            repository_dir.path(),
            created.commit_id,
            &Verification {
                fixture: &fixture,
                bound_stamps: &[],
            },
        )
        .expect("the sealed stamp verifies");
        assert_eq!(summary.accepted.len(), 1);
        assert_eq!(summary.accepted[0].site, "loop");
        run_git(repository_dir.path(), &["fsck", "--strict"]);
    }

    #[test]
    fn the_sealed_message_carries_the_tydence_stamp_trailers() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let created = stamp_head(repository_dir.path(), &fixture)
            .expect("the first stamp seals");
        let manifest_bytes = blob_bytes_at(
            repository_dir.path(),
            created.commit_id,
            MANIFEST_PATH,
        );
        assert_eq!(created.manifest_hashes, hash_payload(&manifest_bytes));
        let message =
            run_git(repository_dir.path(), &["log", "-1", "--format=%B"]);
        let expected_hashes = hash_payload(&manifest_bytes);
        assert_eq!(
            message,
            format!(
                "stamp fixture\n\n\
                 Tydence-Stamp: sha256:{}\n\
                 Tydence-Stamp: sha3-256:{}",
                hex::encode(hex::LOWERCASE, &expected_hashes.sha256),
                hex::encode(hex::LOWERCASE, &expected_hashes.sha3_256),
            )
        );
    }

    #[test]
    fn a_second_stamp_binds_and_seals_the_first_stamps_deposit() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let first = stamp_head(repository_dir.path(), &fixture)
            .expect("the first stamp seals");
        let first_manifest_bytes = blob_bytes_at(
            repository_dir.path(),
            first.commit_id,
            MANIFEST_PATH,
        );
        let first_token_bytes = blob_bytes_at(
            repository_dir.path(),
            first.commit_id,
            &format!("{TOKENS_PATH}/loop.tsr"),
        );
        // Ordinary work continues: the next commit picks up the
        // deposited LTV material and drops the stamp artifacts,
        // which live in the stamp commit's tree, not the worktree.
        fs::write(repository_dir.path().join("more.txt"), b"more\n")
            .expect("the file writes");
        run_git(repository_dir.path(), &["add", "-A"]);
        run_git(repository_dir.path(), &["commit", "-q", "-m", "more"]);
        let second = stamp_head(repository_dir.path(), &fixture)
            .expect("the second stamp seals");
        let second_manifest_bytes = blob_bytes_at(
            repository_dir.path(),
            second.commit_id,
            MANIFEST_PATH,
        );
        let second_manifest_text = String::from_utf8(second_manifest_bytes)
            .expect("the manifest is text");
        let second_manifest = parse_manifest(&second_manifest_text)
            .expect("the manifest parses");
        // The renewal chain: exactly the first stamp is bound.
        assert_eq!(second_manifest.binding_groups.len(), 1);
        let group = &second_manifest.binding_groups[0];
        assert_eq!(group.commit, first.commit_id.to_string());
        assert_eq!(group.manifest_hashes, hash_payload(&first_manifest_bytes));
        assert_eq!(group.tokens.len(), 1);
        assert_eq!(group.tokens[0].site, "loop");
        // The first stamp's deposit is sealed now.
        let paths = entry_paths(&second_manifest_text);
        assert!(
            paths
                .iter()
                .any(|path| path.starts_with(b".tydence/ltv/certs/"))
        );
        assert!(
            paths
                .iter()
                .any(|path| path.starts_with(b".tydence/ltv/crls/"))
        );
        // Full verification, renewal linkage included.
        let bound_stamps = [verify::BoundStamp {
            manifest_bytes: &first_manifest_bytes,
            tokens: vec![verify::BoundToken {
                spec: AnchorSpec::Rfc3161,
                site: "loop".to_string(),
                bytes: &first_token_bytes,
            }],
        }];
        let summary = verified_summary(
            repository_dir.path(),
            second.commit_id,
            &Verification {
                fixture: &fixture,
                bound_stamps: &bound_stamps,
            },
        )
        .expect("the second stamp verifies with its binding");
        assert_eq!(summary.accepted.len(), 1);
        run_git(repository_dir.path(), &["fsck", "--strict"]);
    }

    #[test]
    fn a_follow_up_stamp_alone_seals_the_previous_stamps_deposit() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let first = stamp_head(repository_dir.path(), &fixture)
            .expect("the first stamp seals");
        let first_manifest_text = String::from_utf8(blob_bytes_at(
            repository_dir.path(),
            first.commit_id,
            MANIFEST_PATH,
        ))
        .expect("the manifest is text");
        // The first stamp cannot cover its own deposit: the chain
        // was learned only after the manifest was fixed.
        assert!(
            !entry_paths(&first_manifest_text)
                .iter()
                .any(|path| path.starts_with(LTV_CERTS_PATH.as_bytes()))
        );
        // No ordinary commit in between: the follow-up stamp itself
        // seals the deposit (§5) — the zero-content-change form that
        // makes a freshly adopted site self-contained.
        let second = stamp_head(repository_dir.path(), &fixture)
            .expect("the second stamp seals");
        let second_manifest_text = String::from_utf8(blob_bytes_at(
            repository_dir.path(),
            second.commit_id,
            MANIFEST_PATH,
        ))
        .expect("the manifest is text");
        let paths = entry_paths(&second_manifest_text);
        assert!(
            paths
                .iter()
                .any(|path| path.starts_with(LTV_CERTS_PATH.as_bytes()))
        );
        assert!(
            paths
                .iter()
                .any(|path| path.starts_with(LTV_CRLS_PATH.as_bytes()))
        );
        run_git(repository_dir.path(), &["fsck", "--strict"]);
    }

    #[test]
    fn an_unverified_token_leaves_no_record_behind() {
        let mut fixture = live_fixture();
        // With no trust anchors, every token is refused at pre-seal
        // verification — after its chain material was harvested.
        fixture.anchors.clear();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let verdict = stamp_head(repository_dir.path(), &fixture);
        assert!(matches!(verdict, Err(Error::Acquire(_))));
        // The harvest died in memory: nothing settled on disk that a
        // later refresh would keep renewing.
        assert!(!repository_dir.path().join(LTV_CERTS_PATH).exists());
        assert!(!repository_dir.path().join(LTV_CRLS_PATH).exists());
    }

    #[test]
    fn a_repository_without_a_configuration_cannot_stamp() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        init_repository(repository_dir.path());
        fs::write(repository_dir.path().join("work.txt"), b"payload\n")
            .expect("the file writes");
        run_git(repository_dir.path(), &["add", "-A"]);
        run_git(repository_dir.path(), &["commit", "-q", "-m", "content"]);
        let verdict = stamp_head(repository_dir.path(), &fixture);
        assert!(matches!(verdict, Err(Error::MissingConfig)));
    }

    #[test]
    fn an_unknown_profile_aborts_before_any_exchange() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        init_repository(repository_dir.path());
        // The configuration defines no profile named "solo".
        fs::create_dir_all(repository_dir.path().join(".tydence"))
            .expect("directories are created");
        fs::write(
            repository_dir.path().join(CONFIG_PATH),
            format!(
                "Site loop\n\tURL {}\n\tImprint sha256\n",
                https_spelling(&fixture.tsa_url)
            ),
        )
        .expect("the configuration writes");
        run_git(repository_dir.path(), &["add", "-A"]);
        run_git(repository_dir.path(), &["commit", "-q", "-m", "content"]);
        let verdict = stamp_head(repository_dir.path(), &fixture);
        assert!(matches!(
            verdict,
            Err(Error::Acquire(acquire::Error::UnknownProfile { .. }))
        ));
    }
}
