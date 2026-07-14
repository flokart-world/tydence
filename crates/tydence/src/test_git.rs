//! Git fixture harness for tests: builds throwaway repositories
//! through the git CLI so fixtures exercise real object stores
//! instead of hand-mocked ones.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Pins identity and behavior so fixture repositories build the same
/// everywhere, whatever the host's git configuration says.
pub const GIT_TEST_CONFIG: &[&str] = &[
    "-c",
    "user.name=tydence-test",
    "-c",
    "user.email=tydence-test@example.invalid",
    "-c",
    "protocol.file.allow=always",
    "-c",
    "commit.gpgsign=false",
];

pub fn run_git(repository_dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_dir)
        .args(GIT_TEST_CONFIG)
        .args(args)
        .output()
        .expect("git executes");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

pub fn init_repository(repository_dir: &Path) {
    fs::create_dir_all(repository_dir).expect("directory is created");
    run_git(repository_dir, &["init", "-q"]);
    // The -c pins reach git CLI calls only; the library opens these
    // repositories through gix, which reads the repository
    // configuration instead. Persisting the same pins locally keeps
    // the suite hermetic on hosts without a global git identity —
    // CI containers have none.
    for pin in GIT_TEST_CONFIG.iter().filter(|argument| **argument != "-c") {
        let (key, value) = pin.split_once('=').expect("a -c pin is key=value");
        run_git(repository_dir, &["config", "--local", key, value]);
    }
}

pub fn commit_all(repository_dir: &Path) {
    run_git(repository_dir, &["add", "-A"]);
    run_git(repository_dir, &["commit", "-q", "-m", "fixture"]);
}

/// The id of the commit `revision` names, as gix sees it.
pub fn commit_id_of(repository_dir: &Path, revision: &str) -> gix::ObjectId {
    let hex_id = run_git(repository_dir, &["rev-parse", revision]);
    gix::ObjectId::from_hex(hex_id.as_bytes())
        .expect("rev-parse prints a valid id")
}

/// The blob bytes at `path` in the tree of `commit_id`.
pub fn blob_bytes_at(
    repository_dir: &Path,
    commit_id: gix::ObjectId,
    path: &str,
) -> Vec<u8> {
    let repository =
        gix::open(repository_dir).expect("fixture repository opens");
    let entry = repository
        .find_commit(commit_id)
        .expect("the commit exists")
        .tree()
        .expect("the commit has a tree")
        .lookup_entry_by_path(path)
        .expect("the tree reads")
        .unwrap_or_else(|| panic!("{path:?} should be present"));
    repository
        .find_blob(entry.object_id())
        .expect("the blob exists")
        .take_data()
}
