//! Repository audit: the verification flow a checkout is judged by.
//! From a starting commit, every line of history is followed to its
//! nearest claiming commit — the stamps whose evidence carries the
//! current content — and each claim receives the full fail-closed
//! verdict (stamping specification §7). Bound stamps are resolved by
//! their `--commit` annotations for the renewal-chain linkage of
//! check 4. CRL snapshots and companion certificates are enumerated
//! — never derived by name — from the sealed `ltv/` records of the
//! starting commit and the judged claims, supplemented by the
//! working tree's not-yet-sealed deposits; those deposits are also
//! reported, so the user can be urged to seal them with a follow-up
//! commit.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use super::claims;
use super::deposits;
use super::layout::REGULAR_FILE_MODE;
use super::manifest::{AnchorSpec, parse_manifest};
use super::snapshot;
use super::trust;
use super::verify::{
    self, BoundStamp, BoundToken, SiteToken, StampInputs, StampSummary,
    TrustData, verify_stamp,
};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

/// What one repository audit consumes beyond the repository itself.
#[derive(Debug)]
pub struct AuditInputs<'a> {
    /// The commit the audit starts from, HEAD ordinarily.
    pub start_id: gix::ObjectId,
    /// Trust anchor certificates, DER — the verifier's axioms,
    /// supplied from outside the repository, which must not certify
    /// itself.
    pub anchor_certificates: &'a [Vec<u8>],
    /// The working tree holding not-yet-sealed LTV deposits; absent
    /// for a bare repository.
    pub worktree: Option<&'a Path>,
}

/// The audit could not even be assembled. Unlike a failing claim,
/// which is a verdict, these are environmental: broken objects,
/// records that are not what the layout says they are.
#[derive(Debug)]
pub enum Error {
    /// Git objects needed to assemble the audit could not be read.
    ObjectAccess { source: FailureCause },
    /// The walk to the nearest claims failed.
    Claims(claims::Error),
    /// A sealed `ltv/` record is not laid out as §3 prescribes.
    ForeignLtvRecord { location: String, path: String },
    /// An `ltv/` record did not decode as the trust material its
    /// name announces.
    Material(trust::Error),
    /// The working tree's `ltv/` deposits could not be read.
    Worktree { path: String, source: FailureCause },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectAccess { .. } => {
                write!(formatter, "cannot read git objects")
            }
            Self::Claims(cause) => {
                write!(formatter, "cannot walk to the nearest claims: {cause}")
            }
            Self::ForeignLtvRecord { location, path } => write!(
                formatter,
                "{path:?} in {location} is not laid out as an LTV record"
            ),
            Self::Material(cause) => {
                write!(formatter, "trust material does not decode: {cause}")
            }
            Self::Worktree { path, .. } => write!(
                formatter,
                "cannot read the working tree deposit at {path:?}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectAccess { source } | Self::Worktree { source, .. } => {
                Some(source.as_ref())
            }
            Self::Claims(cause) => Some(cause),
            Self::Material(cause) => Some(cause),
            Self::ForeignLtvRecord { .. } => None,
        }
    }
}

/// Why one claim failed its audit. Anything undecidable fails the
/// claim, never the whole audit: the other claims' verdicts must
/// still reach the user.
#[derive(Debug)]
pub enum ClaimFailure {
    /// Git objects of the claim could not be read.
    ObjectAccess { source: FailureCause },
    /// The claim's artifacts are not laid out as §3 prescribes.
    Artifacts(claims::Error),
    /// The claim's snapshot does not enumerate for check 2.
    Snapshot(snapshot::Error),
    /// A binding group's `--commit` annotation locates no readable
    /// claim in this repository, so check 4 has no bytes to judge.
    UnresolvableBinding {
        commit: String,
        source: FailureCause,
    },
    /// The verdict itself (§7) failed.
    Verdict(verify::Error),
}

impl fmt::Display for ClaimFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectAccess { .. } => {
                write!(formatter, "cannot read the claim's git objects")
            }
            Self::Artifacts(cause) => {
                write!(formatter, "the claim's artifacts do not read: {cause}")
            }
            Self::Snapshot(cause) => {
                write!(formatter, "the snapshot does not enumerate: {cause}")
            }
            Self::UnresolvableBinding { commit, .. } => write!(
                formatter,
                "the bound stamp at commit {commit} cannot be resolved"
            ),
            Self::Verdict(cause) => write!(formatter, "{cause}"),
        }
    }
}

impl std::error::Error for ClaimFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectAccess { source }
            | Self::UnresolvableBinding { source, .. } => {
                Some(source.as_ref())
            }
            Self::Artifacts(cause) => Some(cause),
            Self::Snapshot(cause) => Some(cause),
            Self::Verdict(cause) => Some(cause),
        }
    }
}

/// One judged claim.
#[derive(Debug)]
pub struct ClaimVerdict {
    pub commit_id: gix::ObjectId,
    pub outcome: Result<StampSummary, ClaimFailure>,
}

/// The assembled audit of one starting commit.
#[derive(Debug)]
pub struct Audit {
    /// Whether the starting commit itself carries the claim; when
    /// false, content has moved on since the nearest stamps and is
    /// carried by transport-layer integrity alone.
    pub start_is_claiming: bool,
    /// One verdict per nearest claim behind the start, every line of
    /// history covered. Empty when no line carries a stamp at all.
    pub verdicts: Vec<ClaimVerdict>,
    /// Working-tree LTV records the starting commit's tree does not
    /// carry, as repository paths: evidence that only a follow-up
    /// commit will seal.
    pub unsealed_deposits: Vec<String>,
}

/// The deduplicated union of trust material gathered from every
/// source, DER: sealed records accumulate across trees and the same
/// snapshot may appear in several of them.
struct Material {
    companions: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    seen_companions: HashSet<Vec<u8>>,
    seen_crls: HashSet<Vec<u8>>,
}

impl Material {
    fn new() -> Self {
        Self {
            companions: Vec::new(),
            crls: Vec::new(),
            seen_companions: HashSet::new(),
            seen_crls: HashSet::new(),
        }
    }

    /// Decodes one record into the union, whichever kind it is.
    fn absorb(
        &mut self,
        record: &deposits::DepositRecord,
    ) -> Result<(), Error> {
        match record.kind {
            deposits::DepositKind::Chain => {
                let companions = trust::certificates_from_pem(
                    &record.pem_bytes,
                    &record.repository_path,
                )
                .map_err(Error::Material)?;
                for der_bytes in companions {
                    if self.seen_companions.insert(der_bytes.clone()) {
                        self.companions.push(der_bytes);
                    }
                }
            }
            deposits::DepositKind::Crl => {
                let der_bytes = trust::crl_from_pem(
                    &record.pem_bytes,
                    &record.repository_path,
                )
                .map_err(Error::Material)?;
                if self.seen_crls.insert(der_bytes.clone()) {
                    self.crls.push(der_bytes);
                }
            }
        }
        Ok(())
    }
}

/// Reads the LTV records of one layout in a commit's tree. The
/// directory may be absent; anything present must be a regular file
/// named as the layout prescribes (§3).
fn tree_records(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
    layout: &deposits::RecordLayout,
) -> Result<Vec<deposits::DepositRecord>, Error> {
    let object_access = |source: FailureCause| Error::ObjectAccess { source };
    let tree = repository
        .find_commit(commit_id)
        .map_err(|source| object_access(Box::new(source)))?
        .tree()
        .map_err(|source| object_access(Box::new(source)))?;
    let Some(directory_entry) = tree
        .lookup_entry_by_path(layout.directory_path)
        .map_err(|source| object_access(Box::new(source)))?
    else {
        return Ok(Vec::new());
    };
    if !directory_entry.mode().is_tree() {
        return Err(Error::ForeignLtvRecord {
            location: commit_id.to_string(),
            path: layout.directory_path.to_string(),
        });
    }
    let directory_tree = repository
        .find_tree(directory_entry.object_id())
        .map_err(|source| object_access(Box::new(source)))?;
    let mut records = Vec::new();
    for maybe_entry in directory_tree.iter() {
        let entry =
            maybe_entry.map_err(|source| object_access(Box::new(source)))?;
        let foreign_entry = || Error::ForeignLtvRecord {
            location: commit_id.to_string(),
            path: format!("{}/{}", layout.directory_path, entry.filename()),
        };
        if entry.mode().value() != REGULAR_FILE_MODE {
            return Err(foreign_entry());
        }
        let file_name = std::str::from_utf8(entry.filename())
            .ok()
            .filter(|file_name| file_name.ends_with(layout.suffix))
            .ok_or_else(foreign_entry)?
            .to_string();
        let pem_bytes = repository
            .find_blob(entry.object_id())
            .map_err(|source| object_access(Box::new(source)))?
            .take_data();
        records.push(deposits::DepositRecord {
            kind: layout.kind,
            repository_path: format!("{}/{file_name}", layout.directory_path),
            pem_bytes,
        });
    }
    Ok(records)
}

/// Decodes one commit's sealed LTV records into the material union.
fn gather_tree_material(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
    material: &mut Material,
) -> Result<(), Error> {
    for layout in &deposits::RECORD_LAYOUTS {
        for record in tree_records(repository, commit_id, layout)? {
            material.absorb(&record)?;
        }
    }
    Ok(())
}

/// The blob bytes at `path` in a commit's tree, or `None` when the
/// path holds no regular file there.
fn blob_at(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
    path: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let object_access = |source: FailureCause| Error::ObjectAccess { source };
    let tree = repository
        .find_commit(commit_id)
        .map_err(|source| object_access(Box::new(source)))?
        .tree()
        .map_err(|source| object_access(Box::new(source)))?;
    let Some(entry) = tree
        .lookup_entry_by_path(path)
        .map_err(|source| object_access(Box::new(source)))?
    else {
        return Ok(None);
    };
    if entry.mode().value() != REGULAR_FILE_MODE {
        return Ok(None);
    }
    let bytes = repository
        .find_blob(entry.object_id())
        .map_err(|source| object_access(Box::new(source)))?
        .take_data();
    Ok(Some(bytes))
}

/// Decodes the working tree's deposits into the material union and
/// reports which of them the starting commit's tree does not carry.
/// A bare repository has no working tree and deposits nothing.
fn gather_worktree_material(
    repository: &gix::Repository,
    inputs: &AuditInputs<'_>,
    material: &mut Material,
) -> Result<Vec<String>, Error> {
    let Some(worktree) = inputs.worktree else {
        return Ok(Vec::new());
    };
    let records =
        deposits::enumerate(worktree).map_err(|cause| match cause {
            deposits::Error::Foreign { path } => Error::ForeignLtvRecord {
                location: "the working tree".to_string(),
                path,
            },
            deposits::Error::Unreadable { path, source } => {
                Error::Worktree { path, source }
            }
        })?;
    let mut unsealed = Vec::new();
    for record in &records {
        material.absorb(record)?;
        let sealed =
            blob_at(repository, inputs.start_id, &record.repository_path)?;
        if sealed.as_deref() != Some(record.pem_bytes.as_slice()) {
            unsealed.push(record.repository_path.clone());
        }
    }
    Ok(unsealed)
}

/// Judges one claim with the full verdict, resolving its bound
/// stamps by their `--commit` annotations first.
fn judge_claim(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
    trust_data: TrustData<'_>,
) -> Result<StampSummary, ClaimFailure> {
    let object_access =
        |source: FailureCause| ClaimFailure::ObjectAccess { source };
    let artifacts = claims::read_claim_artifacts(repository, commit_id)
        .map_err(ClaimFailure::Artifacts)?;
    let tree_id = repository
        .find_commit(commit_id)
        .map_err(|source| object_access(Box::new(source)))?
        .tree_id()
        .map_err(|source| object_access(Box::new(source)))?
        .detach();
    let tree_entries =
        snapshot::run(repository, tree_id).map_err(ClaimFailure::Snapshot)?;
    // When the manifest does not even parse, the verdict below is
    // left to report it as its check 1 failure; there are no binding
    // groups to resolve on that path anyway.
    let binding_groups = std::str::from_utf8(&artifacts.manifest_bytes)
        .ok()
        .and_then(|manifest_text| parse_manifest(manifest_text).ok())
        .map(|manifest| manifest.binding_groups)
        .unwrap_or_default();
    let mut resolved: Vec<claims::ClaimArtifacts> = Vec::new();
    for group in &binding_groups {
        let unresolvable =
            |source: FailureCause| ClaimFailure::UnresolvableBinding {
                commit: group.commit.clone(),
                source,
            };
        if group.predecessor_origin.is_some() {
            return Err(unresolvable(
                "the bound stamp lives in a predecessor repository; \
                 supplying its artifacts from outside is not supported yet"
                    .into(),
            ));
        }
        let bound_id = gix::ObjectId::from_hex(group.commit.as_bytes())
            .map_err(|source| unresolvable(Box::new(source)))?;
        let bound_artifacts =
            claims::read_claim_artifacts(repository, bound_id)
                .map_err(|source| unresolvable(Box::new(source)))?;
        resolved.push(bound_artifacts);
    }
    let bound_stamps: Vec<BoundStamp<'_>> = resolved
        .iter()
        .map(|bound| BoundStamp {
            manifest_bytes: &bound.manifest_bytes,
            tokens: bound
                .tokens
                .iter()
                .map(|token_file| BoundToken {
                    spec: AnchorSpec::Rfc3161,
                    site: token_file.site.clone(),
                    bytes: &token_file.bytes,
                })
                .collect(),
        })
        .collect();
    let site_tokens: Vec<SiteToken<'_>> = artifacts
        .tokens
        .iter()
        .map(|token_file| SiteToken {
            site: &token_file.site,
            bytes: &token_file.bytes,
        })
        .collect();
    verify_stamp(&StampInputs {
        manifest_bytes: &artifacts.manifest_bytes,
        tree_entries: &tree_entries,
        tokens: &site_tokens,
        bound_stamps: &bound_stamps,
        trust: trust_data,
    })
    .map_err(ClaimFailure::Verdict)
}

/// Audits one starting commit: judges the nearest claim on every
/// line of history behind it with the full fail-closed verdict.
pub fn run(
    repository: &gix::Repository,
    inputs: &AuditInputs<'_>,
) -> Result<Audit, Error> {
    let claiming =
        claims::nearest_claiming_commits(repository, &[inputs.start_id])
            .map_err(Error::Claims)?;
    let mut material = Material::new();
    let mut material_sources: Vec<gix::ObjectId> = vec![inputs.start_id];
    material_sources.extend(
        claiming
            .iter()
            .filter(|commit_id| **commit_id != inputs.start_id),
    );
    for commit_id in &material_sources {
        gather_tree_material(repository, *commit_id, &mut material)?;
    }
    let unsealed_deposits =
        gather_worktree_material(repository, inputs, &mut material)?;
    let trust_data = TrustData {
        anchor_certificates: inputs.anchor_certificates,
        companion_certificates: &material.companions,
        crls: &material.crls,
    };
    let verdicts = claiming
        .iter()
        .map(|commit_id| ClaimVerdict {
            commit_id: *commit_id,
            outcome: judge_claim(repository, *commit_id, trust_data),
        })
        .collect();
    Ok(Audit {
        start_is_claiming: claiming.contains(&inputs.start_id),
        verdicts,
        unsealed_deposits,
    })
}

#[cfg(test)]
use super::{manifest, test_git, test_stamp};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::manifest::{BindingGroup, Manifest, hash_payload};
    use super::test_git::{commit_id_of, init_repository, run_git};
    use super::test_stamp::{live_fixture, prepare_repository, stamp_head};

    use super::*;

    fn audit_head(
        repository_dir: &Path,
        anchors: &[Vec<u8>],
        worktree: Option<&Path>,
    ) -> Audit {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        run(
            &repository,
            &AuditInputs {
                start_id: commit_id_of(repository_dir, "HEAD"),
                anchor_certificates: anchors,
                worktree,
            },
        )
        .expect("the audit assembles")
    }

    fn ordinary_commit(repository_dir: &Path, file_name: &str) {
        fs::write(repository_dir.join(file_name), file_name.as_bytes())
            .expect("the file writes");
        run_git(repository_dir, &["add", "-A"]);
        run_git(repository_dir, &["commit", "-q", "-m", file_name]);
    }

    #[test]
    fn a_freshly_stamped_head_passes_on_its_worktree_deposits() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let created = stamp_head(repository_dir.path(), &fixture)
            .expect("the stamp seals");
        let audit = audit_head(
            repository_dir.path(),
            &fixture.anchors,
            Some(repository_dir.path()),
        );
        assert!(audit.start_is_claiming);
        assert_eq!(audit.verdicts.len(), 1);
        assert_eq!(audit.verdicts[0].commit_id, created.commit_id);
        let summary = audit.verdicts[0]
            .outcome
            .as_ref()
            .expect("the fresh stamp passes");
        assert_eq!(summary.accepted.len(), 1);
        assert_eq!(summary.accepted[0].site, "loop");
        // The first use of the site left its trust material as
        // working-tree deposits; the audit leans on them and says so.
        assert!(!audit.unsealed_deposits.is_empty());
    }

    #[test]
    fn sealed_deposits_carry_the_audit_without_a_worktree() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let created = stamp_head(repository_dir.path(), &fixture)
            .expect("the stamp seals");
        // The following ordinary commit seals the deposits and drops
        // the stamp artifacts, which never touch the working tree.
        ordinary_commit(repository_dir.path(), "more.txt");
        let audit = audit_head(repository_dir.path(), &fixture.anchors, None);
        assert!(!audit.start_is_claiming);
        assert_eq!(audit.verdicts.len(), 1);
        assert_eq!(audit.verdicts[0].commit_id, created.commit_id);
        assert!(audit.verdicts[0].outcome.is_ok());
        assert!(audit.unsealed_deposits.is_empty());
    }

    #[test]
    fn a_renewal_stamp_audits_with_its_binding_resolved() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture)
            .expect("the first stamp seals");
        ordinary_commit(repository_dir.path(), "more.txt");
        let second = stamp_head(repository_dir.path(), &fixture)
            .expect("the second stamp seals");
        let audit = audit_head(
            repository_dir.path(),
            &fixture.anchors,
            Some(repository_dir.path()),
        );
        assert!(audit.start_is_claiming);
        assert_eq!(audit.verdicts.len(), 1);
        assert_eq!(audit.verdicts[0].commit_id, second.commit_id);
        assert!(audit.verdicts[0].outcome.is_ok());
        // Everything the second stamp leans on is sealed by now.
        assert!(audit.unsealed_deposits.is_empty());
    }

    #[test]
    fn an_heir_with_a_drifted_tree_fails_until_a_new_stamp_heals_it() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture).expect("the stamp seals");
        // The mistake guarded against: resurrecting the artifacts
        // into the index and committing unrelated work on top.
        run_git(
            repository_dir.path(),
            &["checkout", "HEAD", "--", ".tydence"],
        );
        ordinary_commit(repository_dir.path(), "drift.txt");
        let heir_id = commit_id_of(repository_dir.path(), "HEAD");
        let audit = audit_head(
            repository_dir.path(),
            &fixture.anchors,
            Some(repository_dir.path()),
        );
        assert!(audit.start_is_claiming);
        assert_eq!(audit.verdicts.len(), 1);
        assert_eq!(audit.verdicts[0].commit_id, heir_id);
        assert!(matches!(
            audit.verdicts[0].outcome,
            Err(ClaimFailure::Verdict(verify::Error::Tree(_)))
        ));
        // A new stamp binds the heir's byte-identical artifacts and
        // the audit heals: the claim in front is the one that counts.
        let healing = stamp_head(repository_dir.path(), &fixture)
            .expect("the healing stamp seals");
        let healed = audit_head(
            repository_dir.path(),
            &fixture.anchors,
            Some(repository_dir.path()),
        );
        assert_eq!(healed.verdicts.len(), 1);
        assert_eq!(healed.verdicts[0].commit_id, healing.commit_id);
        assert!(healed.verdicts[0].outcome.is_ok());
    }

    #[test]
    fn a_predecessor_binding_fails_the_claim_for_now() {
        let repository_dir = tempfile::tempdir().expect("tempdir");
        init_repository(repository_dir.path());
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: Some(b"the-previous-epoch".to_vec()),
                manifest_hashes: hash_payload(b"the final manifest"),
                tokens: vec![],
            }],
            entries: vec![],
        };
        fs::create_dir_all(repository_dir.path().join(".tydence"))
            .expect("directories are created");
        fs::write(
            repository_dir.path().join(".tydence/manifest"),
            manifest.serialize().expect("the fixture serializes"),
        )
        .expect("the manifest writes");
        run_git(repository_dir.path(), &["add", "-A"]);
        run_git(repository_dir.path(), &["commit", "-q", "-m", "genesis"]);
        let audit = audit_head(repository_dir.path(), &[], None);
        assert_eq!(audit.verdicts.len(), 1);
        assert!(matches!(
            audit.verdicts[0].outcome,
            Err(ClaimFailure::UnresolvableBinding { .. })
        ));
    }

    #[test]
    fn a_history_without_stamps_audits_empty() {
        let repository_dir = tempfile::tempdir().expect("tempdir");
        init_repository(repository_dir.path());
        ordinary_commit(repository_dir.path(), "base.txt");
        let audit = audit_head(
            repository_dir.path(),
            &[],
            Some(repository_dir.path()),
        );
        assert!(!audit.start_is_claiming);
        assert!(audit.verdicts.is_empty());
        assert!(audit.unsealed_deposits.is_empty());
    }
}
