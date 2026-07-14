//! Snapshot enumeration: walks a git tree and produces the manifest
//! entries covering it, per stamping specification §4.2.

use gix::bstr::{BStr, BString, ByteSlice, ByteVec};
use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;

use super::layout::{MANIFEST_PATH, TOKENS_PATH};
use super::manifest::{Entry, FileMode, hash_payload};

// The stamp's own artifacts are excluded because tokens are received
// only after the manifest is fixed (acyclicity). The exclusion is
// limited to the snapshot root: a submodule's stamp artifacts are
// ordinary tracked content of the outer snapshot.
fn is_excluded_from_root(path_in_repository: &BStr) -> bool {
    path_in_repository == MANIFEST_PATH.as_bytes()
        || path_in_repository
            .strip_prefix(TOKENS_PATH.as_bytes())
            .is_some_and(|below_tokens| below_tokens.first() == Some(&b'/'))
}

// Git's tree-entry mode for a gitlink, S_IFGITLINK in git's own
// source: a submodule commit reference. Compared against the raw
// bits for the same fail-closed reason as decode_file_mode below:
// is_commit() masks with IFMT and would silently accept nonstandard
// variants such as 0o160755.
const GITLINK_MODE: u16 = 0o160000;

// Matching the raw mode bits exactly keeps the enumeration fail
// closed: EntryMode::kind() would classify any nonstandard blob mode
// a historical tree carries (100664 from old git, for example) as
// regular or executable, and silently normalizing would record a
// mode the tree does not actually contain.
fn decode_file_mode(mode: gix::objs::tree::EntryMode) -> Option<FileMode> {
    match mode.value() {
        0o100644 => Some(FileMode::Regular),
        0o100755 => Some(FileMode::Executable),
        0o120000 => Some(FileMode::Symlink),
        _ => None,
    }
}

// A submodule name from .gitmodules is used as a directory below the
// module store; a name walking upwards could open an arbitrary
// repository as the submodule (the vector of CVE-2018-11235).
fn is_safe_module_name(name: &BStr) -> bool {
    !name.is_empty()
        && !name.starts_with(b"/")
        && name.split(|byte| *byte == b'/').all(|component| {
            !component.is_empty()
                && component != b".".as_slice()
                && component != b"..".as_slice()
        })
}

fn join_path(prefix: &BStr, relative_path: &BStr) -> BString {
    let mut joined = BString::from(prefix);
    joined.push_str(relative_path);
    joined
}

/// The failure of one enumeration step. The verdict doctrine is fail
/// closed: any tree content the enumeration cannot fully resolve is
/// an error, never a silent omission.
#[derive(Debug)]
pub enum Error {
    /// The git object layer could not produce bytes the snapshot
    /// needs — a missing or unreadable tree, blob or gitlink commit.
    ObjectAccess {
        path: BString,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The tree carries a mode outside the three the manifest
    /// grammar can spell.
    UnsupportedMode { path: BString, mode_bits: u16 },
    /// A gitlink is present but the same tree has no `.gitmodules`
    /// to name it.
    MissingGitmodules { gitlink_path: BString },
    /// The `.gitmodules` blob of the enumerated tree does not parse.
    MalformedGitmodules {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// `.gitmodules` has no entry whose path matches the gitlink.
    UnmappedGitlink { gitlink_path: BString },
    /// A gitlink resolved to a tree that is already on its own
    /// chain, which would make the traversal loop forever.
    GitlinkCycle { gitlink_path: BString },
    /// The submodule repository could not be opened. Both candidate
    /// locations report their own failure so that a repository that
    /// was never checked out can be told apart from a corrupted one.
    UnavailableSubmodule {
        gitlink_path: BString,
        name: BString,
        store_source: Box<dyn std::error::Error + Send + Sync>,
        embedded_source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ObjectAccess { path, .. } => {
                write!(formatter, "cannot read git objects at {path:?}")
            }
            Error::UnsupportedMode { path, mode_bits } => write!(
                formatter,
                "{path:?} carries unsupported mode {mode_bits:06o}"
            ),
            Error::MissingGitmodules { gitlink_path } => write!(
                formatter,
                "gitlink {gitlink_path:?} without .gitmodules in the tree"
            ),
            Error::MalformedGitmodules { .. } => {
                write!(formatter, ".gitmodules does not parse")
            }
            Error::UnmappedGitlink { gitlink_path } => write!(
                formatter,
                "gitlink {gitlink_path:?} has no .gitmodules entry"
            ),
            Error::GitlinkCycle { gitlink_path } => write!(
                formatter,
                "gitlink {gitlink_path:?} re-enters a tree on its own chain"
            ),
            // Both causes are folded into the message because the
            // std error chain has room for only one source
            Error::UnavailableSubmodule {
                gitlink_path,
                name,
                store_source,
                embedded_source,
            } => write!(
                formatter,
                "submodule {name:?} at {gitlink_path:?} is not available \
                 (module store: {store_source}; embedded: {embedded_source})"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ObjectAccess { source, .. }
            | Error::MalformedGitmodules { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// One repository's tree with its placement in the snapshot: the
/// root, or a submodule tree discovered through a gitlink.
#[derive(Debug)]
struct RepositoryTree {
    repository: gix::Repository,
    tree_id: gix::ObjectId,
    /// The snapshot-global prefix of this repository's paths: empty
    /// at the root, `<submodule path>/` below it.
    path_prefix: BString,
    /// Every tree id on the gitlink chain from the snapshot root
    /// down to this tree, `tree_id` included; `resolve_gitlink`
    /// refuses re-entry so that traversal termination is enforced
    /// rather than assumed.
    ancestor_tree_ids: Vec<gix::ObjectId>,
}

// The .gitmodules of the enumerated tree itself — not the worktree's
// — so that a historical stamp commit resolves the submodule layout
// it was created with. No configuration overrides are applied: the
// entries must be a pure function of the tree.
fn parse_gitmodules(
    repository: &gix::Repository,
    records: &[gix::traverse::tree::recorder::Entry],
) -> Result<Option<gix::submodule::File>, Error> {
    let Some(record) = records.iter().find(|record| {
        record.mode.is_blob() && record.filepath == ".gitmodules"
    }) else {
        return Ok(None);
    };
    let blob = repository.find_blob(record.oid).map_err(|source| {
        Error::ObjectAccess {
            path: record.filepath.clone(),
            source: Box::new(source),
        }
    })?;
    gix::submodule::File::from_bytes(
        &blob.data,
        None::<PathBuf>,
        &gix::config::File::default(),
    )
    .map(Some)
    .map_err(|source| Error::MalformedGitmodules {
        source: Box::new(source),
    })
}

type OpenFailure = Box<dyn std::error::Error + Send + Sync>;

fn open_module_store_repository(
    parent: &gix::Repository,
    name: &BStr,
) -> Result<gix::Repository, OpenFailure> {
    if !is_safe_module_name(name) {
        return Err(OpenFailure::from(
            "the module name walks outside the module store",
        ));
    }
    let store_directory = parent
        .common_dir()
        .join("modules")
        .join(gix::path::from_bstr(name));
    gix::open(&store_directory).map_err(OpenFailure::from)
}

fn open_embedded_repository(
    parent: &gix::Repository,
    gitlink_path: &BStr,
) -> Result<gix::Repository, OpenFailure> {
    let Some(worktree_root) = parent.workdir() else {
        return Err(OpenFailure::from(
            "the superproject repository has no worktree",
        ));
    };
    let worktree_directory =
        worktree_root.join(gix::path::from_bstr(gitlink_path));
    gix::open(&worktree_directory).map_err(OpenFailure::from)
}

fn resolve_gitlink(
    parent: &RepositoryTree,
    maybe_modules: Option<&gix::submodule::File>,
    record: &gix::traverse::tree::recorder::Entry,
) -> Result<RepositoryTree, Error> {
    let gitlink_path =
        join_path(parent.path_prefix.as_bstr(), record.filepath.as_bstr());
    let Some(modules) = maybe_modules else {
        return Err(Error::MissingGitmodules { gitlink_path });
    };
    let Some(name) = modules.name_by_path(record.filepath.as_bstr()) else {
        return Err(Error::UnmappedGitlink { gitlink_path });
    };
    // The module store is tried first: it survives a submodule being
    // deinitialized or moved later in history, which keeps historical
    // stamp commits verifiable. A repository embedded in the worktree
    // (pre-1.7.8 layout) is the fallback.
    let repository = open_module_store_repository(&parent.repository, name)
        .or_else(|store_source| {
            open_embedded_repository(
                &parent.repository,
                record.filepath.as_bstr(),
            )
            .map_err(|embedded_source| (store_source, embedded_source))
        })
        .map_err(|(store_source, embedded_source)| {
            Error::UnavailableSubmodule {
                gitlink_path: gitlink_path.clone(),
                name: name.to_owned(),
                store_source,
                embedded_source,
            }
        })?;
    let object_access = |source: Box<dyn std::error::Error + Send + Sync>| {
        Error::ObjectAccess {
            path: gitlink_path.clone(),
            source,
        }
    };
    let tree_id = repository
        .find_commit(record.oid)
        .map_err(|source| object_access(Box::new(source)))?
        .tree_id()
        .map_err(|source| object_access(Box::new(source)))?
        .detach();
    // A tree re-entering its own chain would loop forever. No way to
    // construct such a hash cycle is known, but liveness must not
    // rest on that staying true for decades (the doctrine already
    // assumes hash properties decay): with this check every chain
    // visits distinct trees out of finite object stores, so the
    // traversal terminates unconditionally.
    if parent.ancestor_tree_ids.contains(&tree_id) {
        return Err(Error::GitlinkCycle { gitlink_path });
    }
    let mut ancestor_tree_ids = parent.ancestor_tree_ids.clone();
    ancestor_tree_ids.push(tree_id);
    let mut path_prefix = gitlink_path;
    path_prefix.push(b'/');
    Ok(RepositoryTree {
        repository,
        tree_id,
        path_prefix,
        ancestor_tree_ids,
    })
}

fn read_entry(
    containing_tree: &RepositoryTree,
    record: &gix::traverse::tree::recorder::Entry,
    mode: FileMode,
) -> Result<Entry, Error> {
    let path = join_path(
        containing_tree.path_prefix.as_bstr(),
        record.filepath.as_bstr(),
    );
    // The blob bytes themselves are hashed — a git blob id never
    // enters the evidence. For a symlink the blob is the target
    // string, exactly the content §4.2 prescribes hashing.
    let blob = containing_tree.repository.find_blob(record.oid).map_err(
        |source| Error::ObjectAccess {
            path: path.clone(),
            source: Box::new(source),
        },
    )?;
    Ok(Entry {
        path: path.into(),
        mode,
        size: blob.data.len() as u64,
        content_hashes: hash_payload(&blob.data),
    })
}

fn traverse_repository_tree(
    entry_sink: &mut Vec<Entry>,
    parent_tree: &RepositoryTree,
) -> Result<Vec<RepositoryTree>, Error> {
    let object_access = |source: Box<dyn std::error::Error + Send + Sync>| {
        Error::ObjectAccess {
            path: parent_tree.path_prefix.clone(),
            source,
        }
    };
    let tree = parent_tree
        .repository
        .find_tree(parent_tree.tree_id)
        .map_err(|source| object_access(Box::new(source)))?;
    let records = tree
        .traverse()
        .breadthfirst
        .files()
        .map_err(|source| object_access(Box::new(source)))?;
    let at_snapshot_root = parent_tree.path_prefix.is_empty();
    let mut gitlink_records = Vec::new();
    for record in &records {
        if record.mode.is_tree() {
            continue;
        }
        if at_snapshot_root && is_excluded_from_root(record.filepath.as_bstr())
        {
            continue;
        }
        if record.mode.value() == GITLINK_MODE {
            gitlink_records.push(record);
            continue;
        }
        let Some(mode) = decode_file_mode(record.mode) else {
            return Err(Error::UnsupportedMode {
                path: join_path(
                    parent_tree.path_prefix.as_bstr(),
                    record.filepath.as_bstr(),
                ),
                mode_bits: record.mode.value(),
            });
        };
        entry_sink.push(read_entry(parent_tree, record, mode)?);
    }
    if gitlink_records.is_empty() {
        return Ok(Vec::new());
    }
    let maybe_modules = parse_gitmodules(&parent_tree.repository, &records)?;
    gitlink_records
        .iter()
        .map(|record| {
            resolve_gitlink(parent_tree, maybe_modules.as_ref(), record)
        })
        .collect()
}

/// Enumerates the manifest entries of the snapshot rooted at
/// `root_tree_id`: every tracked file with its git mode, byte size
/// and double content hash, submodules recursed under their path
/// prefix (stamping specification §4.2). Entry order is unspecified;
/// serialization orders lines canonically.
pub fn run(
    repository: &gix::Repository,
    root_tree_id: gix::ObjectId,
) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    let mut pending_trees = VecDeque::new();
    pending_trees.push_back(RepositoryTree {
        repository: repository.clone(),
        tree_id: root_tree_id,
        path_prefix: BString::default(),
        ancestor_tree_ids: vec![root_tree_id],
    });
    // Every chain visits distinct trees (resolve_gitlink refuses
    // re-entry), so the walk over finite object stores terminates
    while let Some(pending_tree) = pending_trees.pop_front() {
        let discovered =
            traverse_repository_tree(&mut entries, &pending_tree)?;
        pending_trees.extend(discovered);
    }
    Ok(entries)
}

#[cfg(test)]
use super::test_git;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::test_git::{
        GIT_TEST_CONFIG, commit_all, init_repository, run_git,
    };

    use super::*;

    fn hash_git_object(
        repository_dir: &Path,
        object_kind: &str,
        object_bytes: &[u8],
    ) -> gix::ObjectId {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repository_dir)
            .args(GIT_TEST_CONFIG)
            .args(["hash-object", "-w", "-t", object_kind, "--literally"])
            .arg("--stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git spawns");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(object_bytes)
            .expect("object bytes are written");
        let output = child.wait_with_output().expect("git finishes");
        assert!(
            output.status.success(),
            "hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let hex_id = String::from_utf8_lossy(&output.stdout);
        gix::ObjectId::from_hex(hex_id.trim().as_bytes())
            .expect("hash-object prints a valid id")
    }

    fn write_tree_object(
        repository_dir: &Path,
        tree_entries: &[(&str, &[u8], gix::ObjectId)],
    ) -> gix::ObjectId {
        let mut tree_bytes = Vec::new();
        for (mode_literal, name, object_id) in tree_entries {
            tree_bytes.extend_from_slice(mode_literal.as_bytes());
            tree_bytes.push(b' ');
            tree_bytes.extend_from_slice(name);
            tree_bytes.push(0);
            tree_bytes.extend_from_slice(object_id.as_slice());
        }
        hash_git_object(repository_dir, "tree", &tree_bytes)
    }

    fn enumerate_entries_from_head(
        repository_dir: &Path,
    ) -> Result<Vec<Entry>, Error> {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        let tree_id = repository
            .head_tree_id()
            .expect("fixture HEAD has a tree")
            .detach();
        run(&repository, tree_id)
    }

    fn enumerate_entries_from_tree(
        repository_dir: &Path,
        tree_id: gix::ObjectId,
    ) -> Result<Vec<Entry>, Error> {
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        run(&repository, tree_id)
    }

    fn entry_by_path<'entries>(
        entries: &'entries [Entry],
        path: &[u8],
    ) -> &'entries Entry {
        entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap_or_else(|| {
                panic!(
                    "entry {:?} should be present",
                    String::from_utf8_lossy(path)
                )
            })
    }

    fn sorted_paths(entries: &[Entry]) -> Vec<Vec<u8>> {
        let mut paths: Vec<Vec<u8>> =
            entries.iter().map(|entry| entry.path.clone()).collect();
        paths.sort_unstable();
        paths
    }

    #[test]
    fn entries_carry_git_modes_byte_sizes_and_double_content_hashes() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        fs::write(repository_dir.join("a.txt"), b"alpha\n")
            .expect("file is written");
        let script_path = repository_dir.join("run.sh");
        fs::write(&script_path, b"#!/bin/sh\n").expect("file is written");
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
            .expect("permissions are set");
        symlink("a.txt", repository_dir.join("link"))
            .expect("symlink is created");
        commit_all(repository_dir);
        let entries =
            enumerate_entries_from_head(repository_dir).expect("enumeration");
        assert_eq!(entries.len(), 3);
        let regular = entry_by_path(&entries, b"a.txt");
        assert_eq!(regular.mode, FileMode::Regular);
        assert_eq!(regular.size, 6);
        assert_eq!(regular.content_hashes, hash_payload(b"alpha\n"));
        let executable = entry_by_path(&entries, b"run.sh");
        assert_eq!(executable.mode, FileMode::Executable);
        assert_eq!(executable.content_hashes, hash_payload(b"#!/bin/sh\n"));
        let link = entry_by_path(&entries, b"link");
        assert_eq!(link.mode, FileMode::Symlink);
        assert_eq!(link.size, 5);
        assert_eq!(link.content_hashes, hash_payload(b"a.txt"));
    }

    #[test]
    fn the_stamps_own_artifacts_are_excluded_but_ltv_is_covered() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        fs::create_dir_all(repository_dir.join(".tydence/tokens"))
            .expect("directories are created");
        fs::create_dir_all(repository_dir.join(".tydence/ltv/certs"))
            .expect("directories are created");
        fs::write(repository_dir.join(".tydence/manifest"), b"m")
            .expect("file is written");
        fs::write(repository_dir.join(".tydence/tokens/freetsa.tsr"), b"t")
            .expect("file is written");
        fs::write(repository_dir.join(".tydence/ltv/certs/ca.cer"), b"c")
            .expect("file is written");
        // A sibling whose name merely begins with "tokens" must stay
        // covered: the exclusion is the directory, not a name prefix
        fs::write(repository_dir.join(".tydence/tokensx"), b"x")
            .expect("file is written");
        fs::write(repository_dir.join("data.txt"), b"d")
            .expect("file is written");
        commit_all(repository_dir);
        let entries =
            enumerate_entries_from_head(repository_dir).expect("enumeration");
        assert_eq!(
            sorted_paths(&entries),
            vec![
                b".tydence/ltv/certs/ca.cer".to_vec(),
                b".tydence/tokensx".to_vec(),
                b"data.txt".to_vec(),
            ]
        );
    }

    #[test]
    fn submodule_contents_are_enumerated_under_their_path_prefix() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let submodule_dir = fixture.path().join("sub");
        init_repository(&submodule_dir);
        fs::write(submodule_dir.join("inner.txt"), b"inner\n")
            .expect("file is written");
        // The submodule's own stamp artifact is ordinary content of
        // the outer snapshot; only the root's artifacts are excluded
        fs::create_dir_all(submodule_dir.join(".tydence"))
            .expect("directory is created");
        fs::write(submodule_dir.join(".tydence/manifest"), b"sub manifest")
            .expect("file is written");
        commit_all(&submodule_dir);
        let super_dir = fixture.path().join("super");
        init_repository(&super_dir);
        fs::write(super_dir.join("outer.txt"), b"outer\n")
            .expect("file is written");
        commit_all(&super_dir);
        run_git(
            &super_dir,
            &[
                "submodule",
                "--quiet",
                "add",
                submodule_dir.to_str().expect("utf-8 fixture path"),
                "sub",
            ],
        );
        run_git(&super_dir, &["commit", "-q", "-m", "add submodule"]);
        let entries =
            enumerate_entries_from_head(&super_dir).expect("enumeration");
        assert_eq!(
            sorted_paths(&entries),
            vec![
                b".gitmodules".to_vec(),
                b"outer.txt".to_vec(),
                b"sub/.tydence/manifest".to_vec(),
                b"sub/inner.txt".to_vec(),
            ]
        );
        let inner = entry_by_path(&entries, b"sub/inner.txt");
        assert_eq!(inner.content_hashes, hash_payload(b"inner\n"));
    }

    #[test]
    fn nested_submodules_compose_their_path_prefixes() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let inner_dir = fixture.path().join("inner");
        init_repository(&inner_dir);
        fs::write(inner_dir.join("leaf.txt"), b"leaf\n")
            .expect("file is written");
        commit_all(&inner_dir);
        let mid_dir = fixture.path().join("mid");
        init_repository(&mid_dir);
        run_git(
            &mid_dir,
            &[
                "submodule",
                "--quiet",
                "add",
                inner_dir.to_str().expect("utf-8 fixture path"),
                "inner",
            ],
        );
        run_git(&mid_dir, &["commit", "-q", "-m", "add inner"]);
        let outer_dir = fixture.path().join("outer");
        init_repository(&outer_dir);
        run_git(
            &outer_dir,
            &[
                "submodule",
                "--quiet",
                "add",
                mid_dir.to_str().expect("utf-8 fixture path"),
                "mid",
            ],
        );
        run_git(&outer_dir, &["commit", "-q", "-m", "add mid"]);
        run_git(
            &outer_dir.join("mid"),
            &["submodule", "--quiet", "update", "--init"],
        );
        let entries =
            enumerate_entries_from_head(&outer_dir).expect("enumeration");
        assert_eq!(
            sorted_paths(&entries),
            vec![
                b".gitmodules".to_vec(),
                b"mid/.gitmodules".to_vec(),
                b"mid/inner/leaf.txt".to_vec(),
            ]
        );
    }

    #[test]
    fn an_embedded_submodule_repository_is_found_through_the_worktree() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let submodule_dir = fixture.path().join("sub");
        init_repository(&submodule_dir);
        fs::write(submodule_dir.join("inner.txt"), b"inner\n")
            .expect("file is written");
        commit_all(&submodule_dir);
        let submodule_head = run_git(&submodule_dir, &["rev-parse", "HEAD"]);
        let super_dir = fixture.path().join("super");
        init_repository(&super_dir);
        // A clone sitting directly in the worktree (pre-1.7.8 layout)
        // leaves the module store empty, so resolution must fall back
        // to opening the checkout itself
        run_git(
            fixture.path(),
            &[
                "clone",
                "-q",
                submodule_dir.to_str().expect("utf-8 fixture path"),
                super_dir.join("sub").to_str().expect("utf-8 fixture path"),
            ],
        );
        let gitmodules_blob = hash_git_object(
            &super_dir,
            "blob",
            b"[submodule \"sub\"]\n\tpath = sub\n\turl = ./sub\n",
        );
        let gitlink_commit =
            gix::ObjectId::from_hex(submodule_head.as_bytes())
                .expect("rev-parse prints a valid id");
        let tree_id = write_tree_object(
            &super_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", gitlink_commit),
            ],
        );
        let entries = enumerate_entries_from_tree(&super_dir, tree_id)
            .expect("enumeration");
        assert_eq!(
            sorted_paths(&entries),
            vec![b".gitmodules".to_vec(), b"sub/inner.txt".to_vec()]
        );
    }

    #[test]
    fn a_gitlink_without_gitmodules_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            repository_dir,
            &[("160000", b"sub", bogus_commit)],
        );
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(
            &error,
            Error::MissingGitmodules { gitlink_path } if gitlink_path == "sub"
        ));
    }

    #[test]
    fn a_gitlink_absent_from_gitmodules_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let gitmodules_blob = hash_git_object(
            repository_dir,
            "blob",
            b"[submodule \"other\"]\n\tpath = other\n\turl = ./other\n",
        );
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            repository_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", bogus_commit),
            ],
        );
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(
            &error,
            Error::UnmappedGitlink { gitlink_path } if gitlink_path == "sub"
        ));
    }

    #[test]
    fn an_unavailable_submodule_repository_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let gitmodules_blob = hash_git_object(
            repository_dir,
            "blob",
            b"[submodule \"sub\"]\n\tpath = sub\n\turl = ./sub\n",
        );
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            repository_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", bogus_commit),
            ],
        );
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(
            &error,
            Error::UnavailableSubmodule { name, .. } if name == "sub"
        ));
    }

    #[test]
    fn a_module_name_walking_outside_the_store_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let gitmodules_blob = hash_git_object(
            repository_dir,
            "blob",
            b"[submodule \"../evil\"]\n\tpath = sub\n\turl = ./sub\n",
        );
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            repository_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", bogus_commit),
            ],
        );
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        let Error::UnavailableSubmodule {
            name, store_source, ..
        } = error
        else {
            panic!("expected UnavailableSubmodule, got {error:?}");
        };
        assert_eq!(name, "../evil");
        assert_eq!(
            store_source.to_string(),
            "the module name walks outside the module store"
        );
    }

    #[test]
    fn a_gitlink_reentering_its_own_chain_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let submodule_dir = fixture.path().join("sub");
        init_repository(&submodule_dir);
        fs::write(submodule_dir.join("inner.txt"), b"inner\n")
            .expect("file is written");
        commit_all(&submodule_dir);
        let submodule_commit = gix::ObjectId::from_hex(
            run_git(&submodule_dir, &["rev-parse", "HEAD"]).as_bytes(),
        )
        .expect("rev-parse prints a valid id");
        let submodule_tree = gix::ObjectId::from_hex(
            run_git(&submodule_dir, &["rev-parse", "HEAD^{tree}"]).as_bytes(),
        )
        .expect("rev-parse prints a valid id");
        let super_dir = fixture.path().join("super");
        init_repository(&super_dir);
        run_git(
            fixture.path(),
            &[
                "clone",
                "-q",
                submodule_dir.to_str().expect("utf-8 fixture path"),
                super_dir.join("sub").to_str().expect("utf-8 fixture path"),
            ],
        );
        let modules = gix::submodule::File::from_bytes(
            b"[submodule \"sub\"]\n\tpath = sub\n\turl = ./sub\n",
            None::<PathBuf>,
            &gix::config::File::default(),
        )
        .expect("well-formed .gitmodules parses");
        let repository =
            gix::open(&super_dir).expect("fixture repository opens");
        // A real hash cycle cannot be built, so the chain is staged
        // as if an ancestor had already been the submodule's tree;
        // resolution must refuse the re-entry
        let parent = RepositoryTree {
            repository: repository.clone(),
            tree_id: repository.empty_tree().id,
            path_prefix: BString::default(),
            ancestor_tree_ids: vec![
                repository.empty_tree().id,
                submodule_tree,
            ],
        };
        let record = gix::traverse::tree::recorder::Entry {
            mode: gix::objs::tree::EntryKind::Commit.into(),
            filepath: "sub".into(),
            oid: submodule_commit,
        };
        let error = resolve_gitlink(&parent, Some(&modules), &record)
            .expect_err("resolution must fail");
        assert!(matches!(
            &error,
            Error::GitlinkCycle { gitlink_path } if gitlink_path == "sub"
        ));
    }

    #[test]
    fn a_malformed_gitmodules_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        // An unclosed section header is a syntax error, not merely an
        // unknown key, so parsing itself must refuse
        let gitmodules_blob = hash_git_object(
            repository_dir,
            "blob",
            b"[submodule \"sub\"\n\tpath = sub\n",
        );
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            repository_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", bogus_commit),
            ],
        );
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(&error, Error::MalformedGitmodules { .. }));
    }

    #[test]
    fn a_missing_gitlink_commit_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let submodule_dir = fixture.path().join("sub");
        init_repository(&submodule_dir);
        fs::write(submodule_dir.join("inner.txt"), b"inner\n")
            .expect("file is written");
        commit_all(&submodule_dir);
        let super_dir = fixture.path().join("super");
        init_repository(&super_dir);
        fs::write(super_dir.join("outer.txt"), b"outer\n")
            .expect("file is written");
        commit_all(&super_dir);
        run_git(
            &super_dir,
            &[
                "submodule",
                "--quiet",
                "add",
                submodule_dir.to_str().expect("utf-8 fixture path"),
                "sub",
            ],
        );
        run_git(&super_dir, &["commit", "-q", "-m", "add submodule"]);
        let gitmodules_blob = hash_git_object(
            &super_dir,
            "blob",
            &fs::read(super_dir.join(".gitmodules"))
                .expect(".gitmodules is readable"),
        );
        let bogus_commit =
            gix::ObjectId::from_hex(b"aa".repeat(20).as_slice())
                .expect("valid hex");
        let tree_id = write_tree_object(
            &super_dir,
            &[
                ("100644", b".gitmodules", gitmodules_blob),
                ("160000", b"sub", bogus_commit),
            ],
        );
        let error = enumerate_entries_from_tree(&super_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(&error, Error::ObjectAccess { .. }));
    }

    #[test]
    fn a_nonstandard_blob_mode_fails_closed() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let blob_id = hash_git_object(repository_dir, "blob", b"payload");
        let tree_id =
            write_tree_object(repository_dir, &[("100600", b"f", blob_id)]);
        let error = enumerate_entries_from_tree(repository_dir, tree_id)
            .expect_err("enumeration must fail");
        assert!(matches!(
            &error,
            Error::UnsupportedMode { path, mode_bits: 0o100600 }
                if path == "f"
        ));
    }

    #[test]
    fn a_sha256_repository_enumerates_identically() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        fs::create_dir_all(repository_dir).expect("directory is created");
        run_git(repository_dir, &["init", "-q", "--object-format=sha256"]);
        fs::write(repository_dir.join("b.txt"), b"beta\n")
            .expect("file is written");
        commit_all(repository_dir);
        let entries =
            enumerate_entries_from_head(repository_dir).expect("enumeration");
        assert_eq!(entries.len(), 1);
        let entry = entry_by_path(&entries, b"b.txt");
        assert_eq!(entry.content_hashes, hash_payload(b"beta\n"));
    }

    #[test]
    fn an_empty_tree_yields_no_entries() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        let repository =
            gix::open(repository_dir).expect("fixture repository opens");
        let empty_tree_id = repository.empty_tree().id;
        let entries = run(&repository, empty_tree_id).expect("enumeration");
        assert!(entries.is_empty());
    }

    #[test]
    fn paths_keep_the_raw_bytes_git_stores() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let repository_dir = fixture.path();
        init_repository(repository_dir);
        // A space plus a lone 0xE9: not valid UTF-8, so the path
        // must survive as bytes without any lossy conversion
        let raw_name: Vec<u8> = b"caf\xe9 au lait.txt".to_vec();
        let file_name = std::ffi::OsString::from_vec(raw_name.clone());
        fs::write(repository_dir.join(&file_name), b"n")
            .expect("file is written");
        run_git(repository_dir, &["add", "-A"]);
        run_git(repository_dir, &["commit", "-q", "-m", "fixture"]);
        let entries =
            enumerate_entries_from_head(repository_dir).expect("enumeration");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, raw_name);
    }
}
