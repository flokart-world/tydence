//! Index bookkeeping around stamps. A stamp commit is written by the
//! sealing flow without touching the index or the working tree, so
//! three pieces of bookkeeping are the checkout's business: bringing
//! the checkout to agree with the seal so a fresh stamp reads clean,
//! queueing the working tree's LTV deposits so the next commit seals
//! them, and guarding against an ordinary commit made while the
//! artifacts sit in the index — whether left by a stamp or
//! resurrected by a reset — whose commit would become an heir claim
//! that can only fail verification once its tree drifts.

use gix::bstr::{BStr, ByteSlice};
use gix::index::entry::{Flags, Mode, Stat};
use std::fmt;

use super::deposits;
use super::layout::{
    LTV_CERTS_PATH, LTV_CRLS_PATH, MANIFEST_PATH, TOKENS_PATH,
};

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
    /// The sealed objects could not be read.
    Objects { source: FailureCause },
    /// A working-tree stamp artifact could not be written or removed.
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
            Self::Objects { .. } => {
                write!(formatter, "cannot read the sealed objects")
            }
            Self::Worktree { path, .. } => write!(
                formatter,
                "cannot write or remove the working tree artifact at {path:?}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BareRepository => None,
            Self::Deposits(cause) => Some(cause),
            Self::Index { source }
            | Self::Objects { source }
            | Self::Worktree { source, .. } => Some(source.as_ref()),
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

fn objects_error(
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::Objects {
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

/// One stamp-managed file of HEAD's tree: the manifest, a token, or
/// an LTV record the seal covers.
fn sealed_files(
    repository: &gix::Repository,
) -> Result<Vec<(String, gix::ObjectId)>, Error> {
    let head_tree = repository
        .head_commit()
        .map_err(objects_error)?
        .tree()
        .map_err(objects_error)?;
    let mut sealed = Vec::new();
    let maybe_manifest_entry = head_tree
        .lookup_entry_by_path(MANIFEST_PATH)
        .map_err(objects_error)?;
    if let Some(entry) = maybe_manifest_entry
        && entry.mode().is_blob()
    {
        sealed.push((MANIFEST_PATH.to_string(), entry.object_id()));
    }
    for directory in [TOKENS_PATH, LTV_CERTS_PATH, LTV_CRLS_PATH] {
        let maybe_entry = head_tree
            .lookup_entry_by_path(directory)
            .map_err(objects_error)?;
        let Some(entry) = maybe_entry else {
            continue;
        };
        if !entry.mode().is_tree() {
            continue;
        }
        let tree = repository
            .find_tree(entry.object_id())
            .map_err(objects_error)?;
        for maybe_child in tree.iter() {
            let child = maybe_child.map_err(objects_error)?;
            if !child.mode().is_blob() {
                continue;
            }
            sealed.push((
                format!("{directory}/{}", child.filename()),
                child.object_id(),
            ));
        }
    }
    Ok(sealed)
}

/// Brings the working tree and the index to agree with HEAD for the
/// stamp-managed paths — the manifest, the tokens, and the LTV
/// records the seal covers — so a freshly stamped checkout reads
/// clean. Leaving the stamped state for ordinary work is the
/// explicit [`drop_artifacts`]; worktree LTV deposits HEAD does not
/// cover are [`stage_deposits`]'s business and stay untouched.
///
/// The walk is not atomic, but every step writes content derived
/// from HEAD alone, so a failure partway — disk full, say — leaves
/// the seal intact and the sync safe to repeat: running it again
/// converges the checkout.
pub fn sync_artifacts(repository: &gix::Repository) -> Result<(), Error> {
    let worktree = repository
        .workdir()
        .ok_or(Error::BareRepository)?
        .to_owned();
    let sealed = sealed_files(repository)?;
    let mut index = repository.open_index().map_err(index_error)?;
    let mut index_changed = false;
    for (path, blob_id) in &sealed {
        let file_path = worktree.join(path);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| {
                Error::Worktree {
                    path: path.clone(),
                    source: Box::new(source),
                }
            })?;
        }
        let blob = repository.find_blob(*blob_id).map_err(objects_error)?;
        std::fs::write(&file_path, &blob.data).map_err(|source| {
            Error::Worktree {
                path: path.clone(),
                source: Box::new(source),
            }
        })?;
        let path_ref: &BStr = path.as_bytes().into();
        match index.entry_index_by_path(path_ref) {
            Ok(position) => {
                let entry = &mut index.entries_mut()[position];
                if entry.id != *blob_id {
                    entry.id = *blob_id;
                    // A zeroed stat never matches the filesystem,
                    // which makes git re-examine the content instead
                    // of trusting a stat this code did not take.
                    entry.stat = Stat::default();
                    index_changed = true;
                }
            }
            Err(_) => {
                index.dangerously_push_entry(
                    Stat::default(),
                    *blob_id,
                    Flags::empty(),
                    Mode::FILE,
                    path_ref,
                );
                index_changed = true;
            }
        }
    }
    // A token of a site the sealed profile no longer uses would
    // otherwise linger in the checkout and keep it dirty; stale
    // artifacts leave with the stamp that replaced them.
    let sealed_paths: std::collections::HashSet<&[u8]> =
        sealed.iter().map(|(path, _)| path.as_bytes()).collect();
    let is_stale = |path: &BStr| {
        is_stamp_artifact(path) && !sealed_paths.contains(path.as_bytes())
    };
    let stale: Vec<String> = index
        .entries_with_paths_by_filter_map(|path, _entry| {
            is_stale(path).then_some(())
        })
        .map(|(path, ())| path.to_string())
        .collect();
    for path in &stale {
        let file_path = worktree.join(path);
        if file_path.is_file() {
            std::fs::remove_file(&file_path).map_err(|source| {
                Error::Worktree {
                    path: path.clone(),
                    source: Box::new(source),
                }
            })?;
        }
    }
    if !stale.is_empty() {
        index.remove_entries(|_position, path, _entry| is_stale(path));
        index_changed = true;
    }
    if index_changed {
        index.sort_entries();
        index.write(write_options()).map_err(index_error)?;
    }
    Ok(())
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
    fn a_fresh_stamp_reads_clean_up_to_its_deposits() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture).expect("the stamp seals");
        sync_artifacts(&open(repository_dir.path()))
            .expect("the checkout syncs");
        stage_deposits(&open(repository_dir.path()))
            .expect("the deposits stage");
        // The artifacts are in place and the only difference left is
        // the queued first-use deposit.
        assert!(repository_dir.path().join(MANIFEST_PATH).is_file());
        assert!(
            repository_dir
                .path()
                .join(TOKENS_PATH)
                .join("loop.tsr")
                .is_file()
        );
        let status =
            run_git(repository_dir.path(), &["status", "--porcelain"]);
        // Presence and exclusivity are separate claims: `all` alone
        // would hold vacuously on an empty status.
        assert!(status.lines().count() >= 1, "no deposit was queued");
        assert!(
            status
                .lines()
                .all(|line| line.starts_with("A  .tydence/ltv/")),
            "unexpected status: {status}"
        );
        // The follow-up stamp seals the deposits; nothing is left.
        stamp_head(repository_dir.path(), &fixture)
            .expect("the second stamp seals");
        sync_artifacts(&open(repository_dir.path()))
            .expect("the second sync succeeds");
        stage_deposits(&open(repository_dir.path()))
            .expect("the second pass stages");
        let settled =
            run_git(repository_dir.path(), &["status", "--porcelain"]);
        assert_eq!(settled, "");
    }

    #[test]
    fn a_stale_artifact_leaves_with_the_stamp_that_replaced_it() {
        let fixture = live_fixture();
        let repository_dir = tempfile::tempdir().expect("tempdir");
        prepare_repository(repository_dir.path(), &fixture);
        stamp_head(repository_dir.path(), &fixture).expect("the stamp seals");
        sync_artifacts(&open(repository_dir.path()))
            .expect("the checkout syncs");
        // A token of a site the sealed profile no longer uses.
        let ghost = repository_dir.path().join(TOKENS_PATH).join("ghost.tsr");
        std::fs::write(&ghost, b"stale").expect("the ghost writes");
        run_git(repository_dir.path(), &["add", ".tydence/tokens/ghost.tsr"]);
        sync_artifacts(&open(repository_dir.path()))
            .expect("the resync succeeds");
        assert!(!ghost.exists());
        let spotted = staged_artifacts(&open(repository_dir.path()))
            .expect("the index reads");
        assert!(!spotted.contains(&".tydence/tokens/ghost.tsr".to_string()));
        assert!(spotted.contains(&".tydence/tokens/loop.tsr".to_string()));
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
