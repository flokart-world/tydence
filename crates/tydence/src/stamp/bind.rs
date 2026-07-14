//! Binding-set construction for one stamp (stamping specification
//! §4.1): every line of history behind the new commit's parents is
//! followed to its nearest preceding stamp commit, and each stamp
//! found becomes one binding group carrying the double hashes of its
//! manifest and token files, returned in the canonical group order.
//!
//! A stamp commit is recognized by carrying `.tydence/manifest` (§2:
//! presence is the claim; validity is verification's question).
//! Ordinary commits after a stamp inherit its artifacts unchanged,
//! so the nearest claim on a line may be such an heir; the group it
//! yields carries the same artifact hashes as the stamp it inherited
//! from, and the differing `--commit` annotation still locates the
//! bytes, so the evidence is unaffected. Heirs on sibling lines
//! collapse into one group below, because a manifest may not repeat
//! a `past-manifest` payload.

use std::fmt;

use super::claims;
use super::manifest::{
    AnchorSpec, BindingGroup, BindingOrderError, PastToken, hash_payload,
    order_binding_groups,
};
use super::verify::{BindingError, BoundStamp, derive_binding_edges};

#[derive(Debug)]
pub enum Error {
    /// A bound claim could not be located or read (git object access,
    /// or artifacts not laid out as §3 prescribes).
    Claim(claims::Error),
    /// The binding relation between the bound stamps could not be
    /// derived because a bound manifest does not parse.
    UnderivableEdges(BindingError),
    /// The derived binding relation does not order (a cycle). Honest
    /// hash bindings cannot produce one, so this is refused rather
    /// than papered over with an arbitrary order.
    Unorderable(BindingOrderError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim(cause) => {
                write!(formatter, "a bound claim cannot be read: {cause}")
            }
            Self::UnderivableEdges(cause) => write!(
                formatter,
                "the binding relation cannot be derived: {cause}"
            ),
            Self::Unorderable(cause) => write!(
                formatter,
                "the binding groups cannot be ordered: {cause}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Claim(cause) => Some(cause),
            Self::UnderivableEdges(cause) => Some(cause),
            Self::Unorderable(cause) => Some(cause),
        }
    }
}

/// One bound stamp's artifacts read off its tree: the group for the
/// manifest under construction, and the manifest bytes kept for
/// deriving the binding relation.
struct ReadStamp {
    group: BindingGroup,
    manifest_bytes: Vec<u8>,
}

fn read_bound_stamp(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
) -> Result<ReadStamp, Error> {
    let artifacts = claims::read_claim_artifacts(repository, commit_id)
        .map_err(Error::Claim)?;
    let tokens = artifacts
        .tokens
        .iter()
        .map(|token_file| PastToken {
            spec: AnchorSpec::Rfc3161,
            site: token_file.site.clone(),
            token_hashes: hash_payload(&token_file.bytes),
        })
        .collect();
    Ok(ReadStamp {
        group: BindingGroup {
            commit: commit_id.to_string(),
            predecessor_origin: None,
            manifest_hashes: hash_payload(&artifacts.manifest_bytes),
            tokens,
        },
        manifest_bytes: artifacts.manifest_bytes,
    })
}

/// Collapses stamps whose manifests hash identically — heirs of one
/// stamp reached over sibling lines, or independent stamps whose
/// manifests coincide byte for byte — because a manifest may not
/// repeat a `past-manifest` payload. The kept `--commit` annotation
/// is the smallest hex among the candidates: annotations carry no
/// evidence, so the choice only has to be deterministic. Only the
/// kept group's token files are renewed; the identical manifests are
/// all bound by the one payload.
fn deduplicate_stamps(read_stamps: Vec<ReadStamp>) -> Vec<ReadStamp> {
    let mut deduplicated: Vec<ReadStamp> = Vec::new();
    for stamp in read_stamps {
        let maybe_kept = deduplicated.iter_mut().find(|kept| {
            kept.group.manifest_hashes == stamp.group.manifest_hashes
        });
        match maybe_kept {
            Some(kept) => {
                if stamp.group.commit < kept.group.commit {
                    *kept = stamp;
                }
            }
            None => deduplicated.push(stamp),
        }
    }
    deduplicated
}

/// Builds the binding set of a new stamp commit with the given
/// parents: one group per nearest preceding stamp on every line of
/// history, in the canonical order of §4.1. A history with no stamp
/// behind any parent — the very first stamp — yields no groups.
pub fn run(
    repository: &gix::Repository,
    parent_ids: &[gix::ObjectId],
) -> Result<Vec<BindingGroup>, Error> {
    let claiming = claims::nearest_claiming_commits(repository, parent_ids)
        .map_err(Error::Claim)?;
    let mut read_stamps = Vec::with_capacity(claiming.len());
    for commit_id in claiming {
        read_stamps.push(read_bound_stamp(repository, commit_id)?);
    }
    let (groups, manifests): (Vec<BindingGroup>, Vec<Vec<u8>>) =
        deduplicate_stamps(read_stamps)
            .into_iter()
            .map(|stamp| (stamp.group, stamp.manifest_bytes))
            .unzip();
    let resolved: Vec<BoundStamp<'_>> = manifests
        .iter()
        .map(|manifest_bytes| BoundStamp {
            manifest_bytes,
            tokens: Vec::new(),
        })
        .collect();
    let edges = derive_binding_edges(&groups, &resolved)
        .map_err(Error::UnderivableEdges)?;
    order_binding_groups(groups, &edges).map_err(Error::Unorderable)
}

#[cfg(test)]
use super::{manifest, test_git};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::manifest::Manifest;
    use super::test_git::{
        commit_all, commit_id_of, init_repository, run_git,
    };

    use super::*;

    fn empty_manifest() -> Manifest {
        Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![],
        }
    }

    // Distinct from empty_manifest() so two independent fixture
    // stamps do not collapse as byte-identical manifests would.
    fn annotated_manifest() -> Manifest {
        Manifest {
            parents: vec!["beef".to_string()],
            binding_groups: vec![],
            entries: vec![],
        }
    }

    fn manifest_binding(bound_manifest_text: &str) -> Manifest {
        Manifest {
            parents: vec![],
            binding_groups: vec![BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: None,
                manifest_hashes: hash_payload(bound_manifest_text.as_bytes()),
                tokens: vec![],
            }],
            entries: vec![],
        }
    }

    fn write_stamp_files(
        repository_dir: &Path,
        manifest: &Manifest,
        tokens: &[(&str, &[u8])],
    ) {
        let manifest_text =
            manifest.serialize().expect("fixture manifests serialize");
        let tokens_dir = repository_dir.join(".tydence/tokens");
        fs::create_dir_all(&tokens_dir).expect("directories are created");
        fs::write(repository_dir.join(".tydence/manifest"), manifest_text)
            .expect("the manifest writes");
        for (site, token_bytes) in tokens {
            fs::write(tokens_dir.join(format!("{site}.tsr")), token_bytes)
                .expect("the token writes");
        }
    }

    fn remove_stamp_files(repository_dir: &Path) {
        fs::remove_dir_all(repository_dir.join(".tydence"))
            .expect("the stamp artifacts are removable");
    }

    fn plain_commit(repository_dir: &Path, file_name: &str) {
        fs::write(repository_dir.join(file_name), file_name.as_bytes())
            .expect("the file writes");
        commit_all(repository_dir);
    }

    fn checkout_new_branch(
        repository_dir: &Path,
        branch: &str,
        start: gix::ObjectId,
    ) {
        run_git(
            repository_dir,
            &["checkout", "-q", "-b", branch, &start.to_string()],
        );
    }

    fn bindings_of(
        repository_dir: &Path,
        parent_ids: &[gix::ObjectId],
    ) -> Result<Vec<BindingGroup>, Error> {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        run(&repository, parent_ids)
    }

    #[test]
    fn a_history_without_stamps_yields_no_groups() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        plain_commit(fixture.path(), "base.txt");
        let head = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[head])
            .expect("a stampless history binds nothing");
        assert!(groups.is_empty());
    }

    #[test]
    fn the_nearest_stamp_past_plain_commits_is_bound() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(
            fixture.path(),
            &empty_manifest(),
            &[("alpha", b"token-alpha")],
        );
        commit_all(fixture.path());
        let stamp = commit_id_of(fixture.path(), "HEAD");
        remove_stamp_files(fixture.path());
        plain_commit(fixture.path(), "work.txt");
        let head = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[head])
            .expect("the stamp behind the plain commit binds");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].commit, stamp.to_string());
        let manifest_text = empty_manifest()
            .serialize()
            .expect("the fixture serializes");
        assert_eq!(
            groups[0].manifest_hashes,
            hash_payload(manifest_text.as_bytes())
        );
        assert_eq!(groups[0].tokens.len(), 1);
        assert_eq!(groups[0].tokens[0].spec, AnchorSpec::Rfc3161);
        assert_eq!(groups[0].tokens[0].site, "alpha");
        assert_eq!(
            groups[0].tokens[0].token_hashes,
            hash_payload(b"token-alpha")
        );
    }

    #[test]
    fn a_parent_that_is_itself_a_stamp_is_bound_directly() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        let stamp = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[stamp])
            .expect("a stamp parent binds itself");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].commit, stamp.to_string());
    }

    #[test]
    fn an_heir_carrying_inherited_artifacts_is_bound_where_it_stands() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        // The artifacts stay in place, as they do in a working tree
        // after a stamp; the follow-up commit inherits them.
        plain_commit(fixture.path(), "work.txt");
        let heir = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[heir])
            .expect("the heir binds in the stamp's stead");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].commit, heir.to_string());
        let manifest_text = empty_manifest()
            .serialize()
            .expect("the fixture serializes");
        assert_eq!(
            groups[0].manifest_hashes,
            hash_payload(manifest_text.as_bytes())
        );
    }

    #[test]
    fn each_merge_side_contributes_its_own_group() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        plain_commit(fixture.path(), "base.txt");
        let base = commit_id_of(fixture.path(), "HEAD");
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        let first_stamp = commit_id_of(fixture.path(), "HEAD");
        checkout_new_branch(fixture.path(), "side", base);
        write_stamp_files(
            fixture.path(),
            &annotated_manifest(),
            &[("beta", b"token-beta")],
        );
        commit_all(fixture.path());
        let second_stamp = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[first_stamp, second_stamp])
            .expect("both sides bind");
        assert_eq!(groups.len(), 2);
        let mut commits: Vec<String> =
            groups.iter().map(|group| group.commit.clone()).collect();
        commits.sort_unstable();
        let mut expected =
            vec![first_stamp.to_string(), second_stamp.to_string()];
        expected.sort_unstable();
        assert_eq!(commits, expected);
        // With no binding relation between the sides, the canonical
        // order is by past-manifest payload bytes.
        assert!(
            groups[0].manifest_hashes.sha256
                <= groups[1].manifest_hashes.sha256
        );
    }

    #[test]
    fn a_stamp_shared_by_both_lines_is_bound_once() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        let stamp = commit_id_of(fixture.path(), "HEAD");
        remove_stamp_files(fixture.path());
        plain_commit(fixture.path(), "one.txt");
        let first_line = commit_id_of(fixture.path(), "HEAD");
        checkout_new_branch(fixture.path(), "side", stamp);
        remove_stamp_files(fixture.path());
        plain_commit(fixture.path(), "two.txt");
        let second_line = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[first_line, second_line])
            .expect("the shared stamp binds once");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].commit, stamp.to_string());
    }

    #[test]
    fn heirs_of_one_stamp_on_sibling_lines_collapse_into_one_group() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        let stamp = commit_id_of(fixture.path(), "HEAD");
        plain_commit(fixture.path(), "one.txt");
        let first_heir = commit_id_of(fixture.path(), "HEAD");
        checkout_new_branch(fixture.path(), "side", stamp);
        plain_commit(fixture.path(), "two.txt");
        let second_heir = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[first_heir, second_heir])
            .expect("identical artifacts collapse");
        assert_eq!(groups.len(), 1);
        // The kept annotation is the smallest hex among the
        // candidates, chosen only for determinism.
        let expected_commit =
            first_heir.to_string().min(second_heir.to_string());
        assert_eq!(groups[0].commit, expected_commit);
    }

    #[test]
    fn a_binder_precedes_the_stamp_it_binds() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        plain_commit(fixture.path(), "base.txt");
        let base = commit_id_of(fixture.path(), "HEAD");
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        commit_all(fixture.path());
        let bound_stamp = commit_id_of(fixture.path(), "HEAD");
        let bound_text = empty_manifest()
            .serialize()
            .expect("the fixture serializes");
        checkout_new_branch(fixture.path(), "side", base);
        write_stamp_files(fixture.path(), &manifest_binding(&bound_text), &[]);
        commit_all(fixture.path());
        let binder_stamp = commit_id_of(fixture.path(), "HEAD");
        let groups = bindings_of(fixture.path(), &[bound_stamp, binder_stamp])
            .expect("the related stamps order");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].commit, binder_stamp.to_string());
        assert_eq!(groups[1].commit, bound_stamp.to_string());
    }

    #[test]
    fn an_unparseable_bound_manifest_fails() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        fs::create_dir_all(fixture.path().join(".tydence"))
            .expect("directories are created");
        fs::write(fixture.path().join(".tydence/manifest"), b"nonsense\n")
            .expect("the manifest writes");
        commit_all(fixture.path());
        let claim = commit_id_of(fixture.path(), "HEAD");
        let verdict = bindings_of(fixture.path(), &[claim]);
        assert!(matches!(verdict, Err(Error::UnderivableEdges(_))));
    }

    #[test]
    fn a_foreign_entry_under_tokens_fails() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        fs::write(
            fixture.path().join(".tydence/tokens/readme.txt"),
            b"not a token",
        )
        .expect("the foreign file writes");
        commit_all(fixture.path());
        let claim = commit_id_of(fixture.path(), "HEAD");
        let verdict = bindings_of(fixture.path(), &[claim]);
        let Err(Error::Claim(claims::Error::ForeignStampArtifact {
            path,
            ..
        })) = verdict
        else {
            panic!("expected ForeignStampArtifact, got {verdict:?}");
        };
        assert_eq!(path, ".tydence/tokens/readme.txt");
    }

    #[test]
    fn a_directory_under_tokens_fails() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        write_stamp_files(fixture.path(), &empty_manifest(), &[]);
        fs::create_dir_all(fixture.path().join(".tydence/tokens/nested"))
            .expect("directories are created");
        fs::write(
            fixture.path().join(".tydence/tokens/nested/x.tsr"),
            b"buried token",
        )
        .expect("the nested file writes");
        commit_all(fixture.path());
        let claim = commit_id_of(fixture.path(), "HEAD");
        let verdict = bindings_of(fixture.path(), &[claim]);
        let Err(Error::Claim(claims::Error::ForeignStampArtifact {
            path,
            ..
        })) = verdict
        else {
            panic!("expected ForeignStampArtifact, got {verdict:?}");
        };
        assert_eq!(path, ".tydence/tokens/nested");
    }

    #[test]
    fn a_manifest_that_is_not_a_regular_file_fails() {
        let fixture = tempfile::tempdir().expect("tempdir");
        init_repository(fixture.path());
        fs::create_dir_all(fixture.path().join(".tydence/manifest"))
            .expect("directories are created");
        fs::write(
            fixture.path().join(".tydence/manifest/fragment"),
            b"not a manifest",
        )
        .expect("the fragment writes");
        commit_all(fixture.path());
        let claim = commit_id_of(fixture.path(), "HEAD");
        let verdict = bindings_of(fixture.path(), &[claim]);
        let Err(Error::Claim(claims::Error::ForeignStampArtifact {
            path,
            ..
        })) = verdict
        else {
            panic!("expected ForeignStampArtifact, got {verdict:?}");
        };
        assert_eq!(path, ".tydence/manifest");
    }
}
