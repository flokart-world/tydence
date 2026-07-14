//! Sealing one stamp (stamping specification §5 steps 6–7): the
//! fixed content, the manifest and the freshly acquired tokens
//! become one commit, written straight into the object database, and
//! the branch reference moves to it under a compare-and-swap
//! expectation — an amend that raced another writer fails instead of
//! silently discarding the other commit.
//!
//! Stale artifacts inherited from an earlier stamp are cleared from
//! the tree: `.tydence/manifest` is replaced and `.tydence/tokens/`
//! is rebuilt to hold exactly the new tokens, so the commit claims
//! precisely what was acquired for it. The working tree is not
//! touched; synchronizing it is the caller's decision.

use gix::objs::tree::EntryKind;
use gix::refs::transaction::{
    Change, LogChange, PreviousValue, RefEdit, RefLog,
};
use std::fmt;

use super::acquire::AcquiredToken;
use super::layout::{MANIFEST_PATH, TOKEN_FILE_SUFFIX, TOKENS_PATH};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// The base tree could not be read or edited.
    TreeEdit { source: FailureCause },
    /// A blob, tree or commit object could not be written.
    ObjectWrite { source: FailureCause },
    /// The reference did not move — the name does not parse, or the
    /// compare-and-swap expectation failed because something else
    /// moved the branch since the stamp began.
    ReferenceUpdate { source: FailureCause },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TreeEdit { .. } => {
                write!(formatter, "the stamp tree could not be built")
            }
            Self::ObjectWrite { .. } => {
                write!(formatter, "the stamp objects could not be written")
            }
            Self::ReferenceUpdate { .. } => {
                write!(formatter, "the branch reference did not move")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TreeEdit { source }
            | Self::ObjectWrite { source }
            | Self::ReferenceUpdate { source } => Some(source.as_ref()),
        }
    }
}

/// Everything one seal consumes. The identity signatures come from
/// the caller: resolving them (configuration, environment) is the
/// command-line layer's business, and fixing them keeps sealing a
/// pure function of its inputs.
#[derive(Debug)]
pub struct SealInputs<'a> {
    /// The tree holding the fixed content to stamp (§5 step 1).
    pub base_tree_id: gix::ObjectId,
    /// The exact bytes of the already fixed `.tydence/manifest`.
    pub manifest_bytes: &'a [u8],
    /// The verified tokens, one file per site.
    pub tokens: &'a [AcquiredToken],
    /// The stamp commit's parents: `[branch tip]` for a new commit,
    /// the tip's own parents for an amend-style replacement.
    pub parent_ids: &'a [gix::ObjectId],
    pub message: &'a str,
    pub author: &'a gix::actor::Signature,
    pub committer: &'a gix::actor::Signature,
    /// The full reference name to move, `refs/heads/...`.
    pub reference_name: &'a str,
    /// What the reference must hold for the move to be allowed;
    /// `MustExistAndMatch(tip)` guards both a child commit and an
    /// amend against concurrent movement.
    pub expected: PreviousValue,
}

fn stamp_tree_id(
    repository: &gix::Repository,
    inputs: &SealInputs<'_>,
) -> Result<gix::ObjectId, Error> {
    let tree_edit = |source: FailureCause| Error::TreeEdit { source };
    let object_write = |source: FailureCause| Error::ObjectWrite { source };
    let mut editor = repository
        .edit_tree(inputs.base_tree_id)
        .map_err(|source| tree_edit(Box::new(source)))?;
    // The fixed content may carry a whole stale tokens directory; a
    // path-by-path upsert would leave alien token files beside the
    // new ones, so the directory is dropped and rebuilt.
    editor
        .remove(TOKENS_PATH)
        .map_err(|source| tree_edit(Box::new(source)))?;
    let manifest_blob = repository
        .write_blob(inputs.manifest_bytes)
        .map_err(|source| object_write(Box::new(source)))?
        .detach();
    editor
        .upsert(MANIFEST_PATH, EntryKind::Blob, manifest_blob)
        .map_err(|source| tree_edit(Box::new(source)))?;
    for token in inputs.tokens {
        let token_blob = repository
            .write_blob(&token.bytes)
            .map_err(|source| object_write(Box::new(source)))?
            .detach();
        editor
            .upsert(
                format!(
                    "{TOKENS_PATH}/{}{TOKEN_FILE_SUFFIX}",
                    token.site_name
                ),
                EntryKind::Blob,
                token_blob,
            )
            .map_err(|source| tree_edit(Box::new(source)))?;
    }
    editor
        .write()
        .map(|tree_id| tree_id.detach())
        .map_err(|source| object_write(Box::new(source)))
}

/// Seals one stamp: writes the stamp tree and commit into the object
/// database and moves the branch reference to it, returning the new
/// commit id.
pub fn run(
    repository: &gix::Repository,
    inputs: &SealInputs<'_>,
) -> Result<gix::ObjectId, Error> {
    let tree_id = stamp_tree_id(repository, inputs)?;
    let commit = gix::objs::Commit {
        tree: tree_id,
        parents: inputs.parent_ids.iter().copied().collect(),
        author: inputs.author.clone(),
        committer: inputs.committer.clone(),
        encoding: None,
        message: inputs.message.into(),
        extra_headers: Vec::new(),
    };
    let commit_id = repository
        .write_object(&commit)
        .map_err(|source| Error::ObjectWrite {
            source: Box::new(source),
        })?
        .detach();
    let reference_name: gix::refs::FullName = inputs
        .reference_name
        .try_into()
        .map_err(|source: gix::refs::name::Error| Error::ReferenceUpdate {
            source: Box::new(source),
        })?;
    repository
        .edit_reference(RefEdit {
            change: Change::Update {
                log: LogChange {
                    mode: RefLog::AndReference,
                    force_create_reflog: false,
                    message: "tydence: seal stamp".into(),
                },
                expected: inputs.expected.clone(),
                new: gix::refs::Target::Object(commit_id),
            },
            name: reference_name,
            deref: false,
        })
        .map_err(|source| Error::ReferenceUpdate {
            source: Box::new(source),
        })?;
    Ok(commit_id)
}

#[cfg(test)]
use super::test_git;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::test_git::{
        blob_bytes_at, commit_id_of, init_repository, run_git,
    };

    use super::*;

    const MANIFEST: &[u8] = b"tydence-manifest/v1\n";

    fn fixture_signature() -> gix::actor::Signature {
        gix::actor::Signature {
            name: "tydence-test".into(),
            email: "tydence-test@example.invalid".into(),
            time: gix::date::Time::new(1_780_000_000, 0),
        }
    }

    fn acquired(site_name: &str, bytes: &[u8]) -> AcquiredToken {
        AcquiredToken {
            site_name: site_name.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    fn seal_onto_head(
        repository_dir: &Path,
        tokens: &[AcquiredToken],
    ) -> Result<gix::ObjectId, Error> {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        let head = commit_id_of(repository_dir, "HEAD");
        let base_tree_id = repository
            .find_commit(head)
            .expect("HEAD is a commit")
            .tree_id()
            .expect("HEAD has a tree")
            .detach();
        let branch = format!(
            "refs/heads/{}",
            run_git(repository_dir, &["branch", "--show-current"])
        );
        let signature = fixture_signature();
        run(
            &repository,
            &SealInputs {
                base_tree_id,
                manifest_bytes: MANIFEST,
                tokens,
                parent_ids: &[head],
                message: "stamp fixture",
                author: &signature,
                committer: &signature,
                reference_name: &branch,
                expected: PreviousValue::MustExistAndMatch(
                    gix::refs::Target::Object(head),
                ),
            },
        )
    }

    fn prepare_plain_repository(repository_dir: &Path) {
        init_repository(repository_dir);
        std::fs::write(repository_dir.join("a.txt"), b"alpha\n")
            .expect("the file writes");
        run_git(repository_dir, &["add", "-A"]);
        run_git(repository_dir, &["commit", "-q", "-m", "base"]);
    }

    #[test]
    fn a_seal_commits_the_manifest_and_tokens_over_the_base_tree() {
        let fixture = tempfile::tempdir().expect("tempdir");
        prepare_plain_repository(fixture.path());
        let base_head = commit_id_of(fixture.path(), "HEAD");
        let sealed = seal_onto_head(
            fixture.path(),
            &[acquired("alpha", b"token-alpha")],
        )
        .expect("the seal succeeds");
        assert_eq!(commit_id_of(fixture.path(), "HEAD"), sealed);
        assert_eq!(
            blob_bytes_at(fixture.path(), sealed, ".tydence/manifest"),
            MANIFEST
        );
        assert_eq!(
            blob_bytes_at(fixture.path(), sealed, ".tydence/tokens/alpha.tsr"),
            b"token-alpha"
        );
        assert_eq!(blob_bytes_at(fixture.path(), sealed, "a.txt"), b"alpha\n");
        assert_eq!(
            run_git(fixture.path(), &["rev-parse", &format!("{sealed}^")],),
            base_head.to_string()
        );
        // The object database must satisfy git itself, not just gix.
        run_git(fixture.path(), &["fsck", "--strict"]);
    }

    #[test]
    fn a_seal_replaces_stale_artifacts_from_the_base_tree() {
        let fixture = tempfile::tempdir().expect("tempdir");
        prepare_plain_repository(fixture.path());
        let tokens_dir = fixture.path().join(".tydence/tokens");
        std::fs::create_dir_all(&tokens_dir).expect("directories are created");
        std::fs::write(
            fixture.path().join(".tydence/manifest"),
            b"stale manifest\n",
        )
        .expect("the stale manifest writes");
        std::fs::write(tokens_dir.join("old.tsr"), b"stale token")
            .expect("the stale token writes");
        run_git(fixture.path(), &["add", "-A"]);
        run_git(fixture.path(), &["commit", "-q", "-m", "stale stamp"]);
        let sealed =
            seal_onto_head(fixture.path(), &[acquired("new", b"fresh")])
                .expect("the seal succeeds");
        assert_eq!(
            blob_bytes_at(fixture.path(), sealed, ".tydence/manifest"),
            MANIFEST
        );
        assert_eq!(
            blob_bytes_at(fixture.path(), sealed, ".tydence/tokens/new.tsr"),
            b"fresh"
        );
        let token_listing = run_git(
            fixture.path(),
            &[
                "ls-tree",
                "--name-only",
                &sealed.to_string(),
                // The trailing slash lists the directory's contents
                // instead of the directory entry itself.
                ".tydence/tokens/",
            ],
        );
        assert_eq!(token_listing, ".tydence/tokens/new.tsr");
    }

    #[test]
    fn an_amend_style_seal_replaces_the_branch_tip() {
        let fixture = tempfile::tempdir().expect("tempdir");
        prepare_plain_repository(fixture.path());
        let grandparent = commit_id_of(fixture.path(), "HEAD");
        std::fs::write(fixture.path().join("b.txt"), b"beta\n")
            .expect("the file writes");
        run_git(fixture.path(), &["add", "-A"]);
        run_git(fixture.path(), &["commit", "-q", "-m", "tip"]);
        let tip = commit_id_of(fixture.path(), "HEAD");
        let repository =
            gix::open(fixture.path()).expect("fixture repository opens");
        let base_tree_id = repository
            .find_commit(tip)
            .expect("the tip exists")
            .tree_id()
            .expect("the tip has a tree")
            .detach();
        let branch = format!(
            "refs/heads/{}",
            run_git(fixture.path(), &["branch", "--show-current"])
        );
        let signature = fixture_signature();
        let sealed = run(
            &repository,
            &SealInputs {
                base_tree_id,
                manifest_bytes: MANIFEST,
                tokens: &[],
                parent_ids: &[grandparent],
                message: "amended stamp",
                author: &signature,
                committer: &signature,
                reference_name: &branch,
                expected: PreviousValue::MustExistAndMatch(
                    gix::refs::Target::Object(tip),
                ),
            },
        )
        .expect("the amend-style seal succeeds");
        assert_eq!(commit_id_of(fixture.path(), "HEAD"), sealed);
        assert_eq!(
            run_git(fixture.path(), &["rev-parse", &format!("{sealed}^")]),
            grandparent.to_string()
        );
        assert_eq!(blob_bytes_at(fixture.path(), sealed, "b.txt"), b"beta\n");
        run_git(fixture.path(), &["fsck", "--strict"]);
    }

    #[test]
    fn a_moved_branch_fails_the_compare_and_swap() {
        let fixture = tempfile::tempdir().expect("tempdir");
        prepare_plain_repository(fixture.path());
        let old_head = commit_id_of(fixture.path(), "HEAD");
        // The branch moves on after the stamp began.
        std::fs::write(fixture.path().join("c.txt"), b"gamma\n")
            .expect("the file writes");
        run_git(fixture.path(), &["add", "-A"]);
        run_git(fixture.path(), &["commit", "-q", "-m", "racer"]);
        let racer = commit_id_of(fixture.path(), "HEAD");
        let repository =
            gix::open(fixture.path()).expect("fixture repository opens");
        let base_tree_id = repository
            .find_commit(old_head)
            .expect("the old head exists")
            .tree_id()
            .expect("the old head has a tree")
            .detach();
        let branch = format!(
            "refs/heads/{}",
            run_git(fixture.path(), &["branch", "--show-current"])
        );
        let signature = fixture_signature();
        let verdict = run(
            &repository,
            &SealInputs {
                base_tree_id,
                manifest_bytes: MANIFEST,
                tokens: &[],
                parent_ids: &[old_head],
                message: "late stamp",
                author: &signature,
                committer: &signature,
                reference_name: &branch,
                expected: PreviousValue::MustExistAndMatch(
                    gix::refs::Target::Object(old_head),
                ),
            },
        );
        assert!(matches!(verdict, Err(Error::ReferenceUpdate { .. })));
        // The other writer's commit survives untouched.
        assert_eq!(commit_id_of(fixture.path(), "HEAD"), racer);
    }
}
