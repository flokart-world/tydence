//! Stamp claims in git history (stamping specification §2): a commit
//! claims to be stamped by carrying `.tydence/manifest`, and the
//! claim's artifacts are laid out as §3 prescribes. Locating the
//! nearest claims behind a commit and reading a claim's artifact
//! bytes are shared ground: binding follows every line of history to
//! the nearest claim it must bind, and repository verification walks
//! the same lines to the claims it must judge.

use std::collections::HashSet;
use std::fmt;

use super::layout::{
    MANIFEST_PATH, REGULAR_FILE_MODE, TOKEN_FILE_SUFFIX, TOKENS_PATH,
};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// The git objects of a commit on the walk could not be read.
    ObjectAccess {
        commit: String,
        source: FailureCause,
    },
    /// A claim's artifacts are not shaped as §3 lays them out:
    /// `.tydence/manifest` is not a regular file, or
    /// `.tydence/tokens/` holds something other than `<site>.tsr`
    /// token files.
    ForeignStampArtifact { commit: String, path: String },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectAccess { commit, .. } => {
                write!(formatter, "cannot read git objects of {commit}")
            }
            Self::ForeignStampArtifact { commit, path } => write!(
                formatter,
                "{path:?} in stamp commit {commit} is not laid out as a \
                 stamp artifact"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectAccess { source, .. } => Some(source.as_ref()),
            Self::ForeignStampArtifact { .. } => None,
        }
    }
}

fn object_access(commit_id: gix::ObjectId, source: FailureCause) -> Error {
    Error::ObjectAccess {
        commit: commit_id.to_string(),
        source,
    }
}

/// One token file of a claim, named after its site (§3).
#[derive(Debug)]
pub struct TokenFile {
    pub site: String,
    pub bytes: Vec<u8>,
}

/// The artifact bytes one claiming commit carries.
#[derive(Debug)]
pub struct ClaimArtifacts {
    pub manifest_bytes: Vec<u8>,
    pub tokens: Vec<TokenFile>,
}

fn tree_of(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
) -> Result<gix::Tree<'_>, Error> {
    repository
        .find_commit(commit_id)
        .map_err(|source| object_access(commit_id, Box::new(source)))?
        .tree()
        .map_err(|source| object_access(commit_id, Box::new(source)))
}

fn manifest_entry<'repo>(
    tree: &gix::Tree<'repo>,
    commit_id: gix::ObjectId,
) -> Result<Option<gix::object::tree::Entry<'repo>>, Error> {
    tree.lookup_entry_by_path(MANIFEST_PATH)
        .map_err(|source| object_access(commit_id, Box::new(source)))
}

fn read_token_files(
    repository: &gix::Repository,
    tree: &gix::Tree<'_>,
    commit_id: gix::ObjectId,
) -> Result<Vec<TokenFile>, Error> {
    let Some(tokens_entry) = tree
        .lookup_entry_by_path(TOKENS_PATH)
        .map_err(|source| object_access(commit_id, Box::new(source)))?
    else {
        return Ok(Vec::new());
    };
    if !tokens_entry.mode().is_tree() {
        return Err(Error::ForeignStampArtifact {
            commit: commit_id.to_string(),
            path: TOKENS_PATH.to_string(),
        });
    }
    let tokens_tree = repository
        .find_tree(tokens_entry.object_id())
        .map_err(|source| object_access(commit_id, Box::new(source)))?;
    let mut token_files = Vec::new();
    for maybe_entry in tokens_tree.iter() {
        let entry = maybe_entry
            .map_err(|source| object_access(commit_id, Box::new(source)))?;
        let foreign_entry = || Error::ForeignStampArtifact {
            commit: commit_id.to_string(),
            path: format!("{TOKENS_PATH}/{}", entry.filename()),
        };
        // §3 lays tokens out flat as regular `<site>.tsr` files;
        // anything else under tokens/ cannot be attributed to a site
        // and is refused rather than skipped.
        if entry.mode().value() != REGULAR_FILE_MODE {
            return Err(foreign_entry());
        }
        let site = std::str::from_utf8(entry.filename())
            .ok()
            .and_then(|file_name| file_name.strip_suffix(TOKEN_FILE_SUFFIX))
            .filter(|site| !site.is_empty())
            .ok_or_else(foreign_entry)?
            .to_string();
        let token_bytes = repository
            .find_blob(entry.object_id())
            .map_err(|source| object_access(commit_id, Box::new(source)))?
            .take_data();
        token_files.push(TokenFile {
            site,
            bytes: token_bytes,
        });
    }
    Ok(token_files)
}

/// Reads the artifact bytes of one claiming commit off its tree.
pub fn read_claim_artifacts(
    repository: &gix::Repository,
    commit_id: gix::ObjectId,
) -> Result<ClaimArtifacts, Error> {
    let tree = tree_of(repository, commit_id)?;
    let entry = manifest_entry(&tree, commit_id)?.ok_or_else(|| {
        Error::ForeignStampArtifact {
            commit: commit_id.to_string(),
            path: MANIFEST_PATH.to_string(),
        }
    })?;
    if entry.mode().value() != REGULAR_FILE_MODE {
        return Err(Error::ForeignStampArtifact {
            commit: commit_id.to_string(),
            path: MANIFEST_PATH.to_string(),
        });
    }
    let manifest_bytes = repository
        .find_blob(entry.object_id())
        .map_err(|source| object_access(commit_id, Box::new(source)))?
        .take_data();
    let tokens = read_token_files(repository, &tree, commit_id)?;
    Ok(ClaimArtifacts {
        manifest_bytes,
        tokens,
    })
}

/// Walks every line of history behind `start_ids` to its nearest
/// commit carrying `.tydence/manifest`. A starting commit that
/// claims itself is its own nearest claim.
pub fn nearest_claiming_commits(
    repository: &gix::Repository,
    start_ids: &[gix::ObjectId],
) -> Result<Vec<gix::ObjectId>, Error> {
    let mut visited: HashSet<gix::ObjectId> = HashSet::new();
    let mut frontier: Vec<gix::ObjectId> = start_ids.to_vec();
    let mut claiming = Vec::new();
    while let Some(commit_id) = frontier.pop() {
        if !visited.insert(commit_id) {
            continue;
        }
        let tree = tree_of(repository, commit_id)?;
        if manifest_entry(&tree, commit_id)?.is_some() {
            claiming.push(commit_id);
            continue;
        }
        let commit = repository
            .find_commit(commit_id)
            .map_err(|source| object_access(commit_id, Box::new(source)))?;
        frontier.extend(commit.parent_ids().map(|parent| parent.detach()));
    }
    Ok(claiming)
}
