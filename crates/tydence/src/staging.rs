//! Index bookkeeping around stamps. A stamp commit is written by the
//! sealing flow without ever touching the index or the working tree,
//! so its artifacts exist only where stamps are — but two pieces of
//! bookkeeping remain the checkout's business: queueing the working
//! tree's LTV deposits so the next commit seals them, and guarding
//! against stamp artifacts resurrected into the index (a reset, say),
//! whose commit would become an heir claim that can only fail
//! verification once its tree drifts.

use gix::bstr::BStr;
use gix::index::entry::{Flags, Mode, Stat};
use std::fmt;

use super::deposits;
use super::layout::{MANIFEST_PATH, TOKENS_PATH};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// The repository has no working tree to hold deposits.
    BareRepository,
    /// The working tree's deposits could not be enumerated.
    Deposits(deposits::Error),
    /// The index could not be read or written.
    Index { source: FailureCause },
    /// A working-tree stamp artifact could not be removed.
    Worktree { path: String, source: FailureCause },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BareRepository => write!(
                formatter,
                "the repository has no working tree to hold deposits"
            ),
            Self::Deposits(cause) => {
                write!(formatter, "the deposits do not enumerate: {cause}")
            }
            Self::Index { .. } => {
                write!(formatter, "cannot read or write the index")
            }
            Self::Worktree { path, .. } => write!(
                formatter,
                "cannot remove the working tree artifact at {path:?}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BareRepository => None,
            Self::Deposits(cause) => Some(cause),
            Self::Index { source } | Self::Worktree { source, .. } => {
                Some(source.as_ref())
            }
        }
    }
}

fn index_error(
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::Index {
        source: Box::new(source),
    }
}

// gix writes the tree-cache extension back as-is, without
// invalidating it against the edited entries, and a stale cache
// would make the next `git commit` write the cached — pre-edit —
// trees. Dropping the optional extensions makes git recompute them.
fn write_options() -> gix::index::write::Options {
    gix::index::write::Options {
        extensions: gix::index::write::Extensions::None,
        ..Default::default()
    }
}

/// Whether an index path is a stamp artifact (§3): the manifest, or
/// anything under the token directory.
fn is_stamp_artifact(path: &BStr) -> bool {
    path == MANIFEST_PATH.as_bytes()
        || path
            .strip_prefix(TOKENS_PATH.as_bytes())
            .is_some_and(|below_tokens| below_tokens.first() == Some(&b'/'))
}

/// Queues the working tree's LTV deposits in the index, so the next
/// commit — stamp or ordinary — seals them. Returns the repository
/// paths whose index entry actually changed; an empty answer means
/// everything was already queued.
pub fn stage_deposits(
    repository: &gix::Repository,
) -> Result<Vec<String>, Error> {
    let worktree = repository
        .workdir()
        .ok_or(Error::BareRepository)?
        .to_owned();
    let records = deposits::enumerate(&worktree).map_err(Error::Deposits)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let mut index = repository.open_index().map_err(index_error)?;
    let mut staged = Vec::new();
    for record in records {
        let blob_id = repository
            .write_blob(&record.pem_bytes)
            .map_err(index_error)?
            .detach();
        let path: &BStr = record.repository_path.as_bytes().into();
        match index.entry_index_by_path(path) {
            Ok(position) => {
                let entry = &mut index.entries_mut()[position];
                if entry.id == blob_id {
                    continue;
                }
                entry.id = blob_id;
                // A zeroed stat never matches the filesystem, which
                // makes git re-examine the content instead of
                // trusting a stat this code did not take.
                entry.stat = Stat::default();
            }
            Err(_) => {
                index.dangerously_push_entry(
                    Stat::default(),
                    blob_id,
                    Flags::empty(),
                    Mode::FILE,
                    path,
                );
            }
        }
        staged.push(record.repository_path);
    }
    if staged.is_empty() {
        return Ok(staged);
    }
    index.sort_entries();
    index.write(write_options()).map_err(index_error)?;
    Ok(staged)
}

/// The stamp artifacts currently staged in the index — what the
/// pre-commit guard refuses, because only the sealing flow may
/// commit them.
pub fn staged_artifacts(
    repository: &gix::Repository,
) -> Result<Vec<String>, Error> {
    let index = repository.index_or_empty().map_err(index_error)?;
    Ok(index
        .entries_with_paths_by_filter_map(|path, _entry| {
            is_stamp_artifact(path).then_some(())
        })
        .map(|(path, ())| path.to_string())
        .collect())
}

/// Declares that the next commit is not a stamp: removes the stamp
/// artifacts from the index and the working tree, leaving everything
/// else — the configuration and the LTV records included — exactly
/// where it is. Returns what was dropped.
pub fn drop_artifacts(
    repository: &gix::Repository,
) -> Result<Vec<String>, Error> {
    let mut dropped = staged_artifacts(repository)?;
    if !dropped.is_empty() {
        let mut index = repository.open_index().map_err(index_error)?;
        index
            .remove_entries(|_position, path, _entry| is_stamp_artifact(path));
        index.write(write_options()).map_err(index_error)?;
    }
    let worktree = repository
        .workdir()
        .ok_or(Error::BareRepository)?
        .to_owned();
    let removal_error = |path: &str| {
        let path = path.to_string();
        move |source: std::io::Error| Error::Worktree {
            path,
            source: Box::new(source),
        }
    };
    let manifest_file = worktree.join(MANIFEST_PATH);
    if manifest_file.is_file() {
        std::fs::remove_file(manifest_file)
            .map_err(removal_error(MANIFEST_PATH))?;
        dropped.push(MANIFEST_PATH.to_string());
    }
    let tokens_directory = worktree.join(TOKENS_PATH);
    if tokens_directory.is_dir() {
        std::fs::remove_dir_all(tokens_directory)
            .map_err(removal_error(TOKENS_PATH))?;
        dropped.push(format!("{TOKENS_PATH}/"));
    }
    dropped.sort();
    dropped.dedup();
    Ok(dropped)
}

#[cfg(test)]
use super::{test_git, test_stamp};

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::test_git::run_git;
    use super::test_stamp::{live_fixture, prepare_repository, stamp_head};

    use super::*;

    fn open(repository_dir: &Path) -> gix::Repository {
        gix::open(repository_dir).expect("fixture repository opens")
    }

    #[test]
    fn deposits_are_queued_once_and_seal_with_the_next_commit() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture).expect("the stamp seals");
        let staged = stage_deposits(&open(repository_dir.path()))
            .expect("the deposits stage");
        assert!(!staged.is_empty());
        assert!(staged.iter().all(|path| path.starts_with(".tydence/ltv/")));
        // Queueing is idempotent: a second pass changes nothing.
        let restaged = stage_deposits(&open(repository_dir.path()))
            .expect("the second pass stages");
        assert!(restaged.is_empty());
        // Git accepts the written index and the next commit seals
        // the queued deposits.
        run_git(repository_dir.path(), &["commit", "-q", "-m", "seal"]);
        let sealed = run_git(
            repository_dir.path(),
            &["ls-tree", "-r", "--name-only", "HEAD"],
        );
        for path in &staged {
            assert!(sealed.lines().any(|line| line == path));
        }
    }

    #[test]
    fn resurrected_artifacts_are_spotted_and_dropped() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture).expect("the stamp seals");
        // The guarded mistake: a reset or checkout resurrects the
        // artifacts into the index and the working tree.
        run_git(
            repository_dir.path(),
            &["checkout", "HEAD", "--", ".tydence"],
        );
        let spotted = staged_artifacts(&open(repository_dir.path()))
            .expect("the index reads");
        assert!(spotted.contains(&".tydence/manifest".to_string()));
        assert!(spotted.contains(&".tydence/tokens/loop.tsr".to_string()));
        assert!(!spotted.iter().any(|path| path == ".tydence/config"));
        let dropped = drop_artifacts(&open(repository_dir.path()))
            .expect("the artifacts drop");
        assert!(!dropped.is_empty());
        let after = staged_artifacts(&open(repository_dir.path()))
            .expect("the index reads");
        assert!(after.is_empty());
        assert!(!repository_dir.path().join(MANIFEST_PATH).exists());
        assert!(!repository_dir.path().join(TOKENS_PATH).exists());
        // Everything that is not a stamp artifact stays.
        assert!(repository_dir.path().join(".tydence/config").exists());
        assert!(repository_dir.path().join(".tydence/ltv").exists());
    }

    #[test]
    fn a_clean_checkout_has_nothing_to_spot_or_drop() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        let repository = open(repository_dir.path());
        assert!(
            staged_artifacts(&repository)
                .expect("the index reads")
                .is_empty()
        );
        assert!(
            drop_artifacts(&repository)
                .expect("the drop is a no-op")
                .is_empty()
        );
    }
}
