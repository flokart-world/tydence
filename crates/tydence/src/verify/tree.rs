//! Verification check 2 (stamping specification §7): bidirectional
//! agreement between the manifest's entries and the actual tree
//! contents.
//!
//! Both directions matter: an entry the tree cannot reproduce breaks
//! the claim, and a tree file the manifest never covered means the
//! stamp does not prove what the checkout shows. The tree side comes
//! from the same snapshot enumeration the stamper uses, so the two
//! sides disagree exactly when the content changed.

use std::collections::BTreeMap;
use std::fmt;

use super::manifest::Entry;

/// One path on which the manifest and the tree disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Disagreement {
    /// The manifest lists the path but the tree does not carry it.
    MissingFromTree { path: Vec<u8> },
    /// The tree carries the path but the manifest does not list it.
    MissingFromManifest { path: Vec<u8> },
    /// Both sides carry the path but with a differing mode, size or
    /// hash.
    ConflictingContent {
        manifest_entry: Entry,
        tree_entry: Entry,
    },
}

impl Disagreement {
    fn path(&self) -> &[u8] {
        match self {
            Self::MissingFromTree { path } => path,
            Self::MissingFromManifest { path } => path,
            Self::ConflictingContent { manifest_entry, .. } => {
                &manifest_entry.path
            }
        }
    }
}

impl fmt::Display for Disagreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self {
            Self::MissingFromTree { .. } => "is not in the tree",
            Self::MissingFromManifest { .. } => "is not in the manifest",
            Self::ConflictingContent { .. } => {
                "differs between manifest and tree"
            }
        };
        write!(
            formatter,
            "{} {cause}",
            String::from_utf8_lossy(self.path())
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A side lists one path twice. One entry per path is the premise
    /// of the comparison, so it refuses to decide anything.
    DuplicateManifestPath {
        path: Vec<u8>,
    },
    DuplicateTreePath {
        path: Vec<u8>,
    },
    /// The sides disagree; every disagreeing path is reported.
    Disagreements(Vec<Disagreement>),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateManifestPath { path } => write!(
                formatter,
                "the manifest lists {} twice",
                String::from_utf8_lossy(path)
            ),
            Self::DuplicateTreePath { path } => write!(
                formatter,
                "the tree enumeration lists {} twice",
                String::from_utf8_lossy(path)
            ),
            Self::Disagreements(disagreements) => {
                write!(
                    formatter,
                    "manifest and tree disagree on {} path(s):",
                    disagreements.len()
                )?;
                for disagreement in disagreements {
                    write!(formatter, " [{disagreement}]")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

fn index_by_path(entries: &[Entry]) -> Result<BTreeMap<&[u8], &Entry>, &[u8]> {
    let mut index: BTreeMap<&[u8], &Entry> = BTreeMap::new();
    for entry in entries {
        if index.insert(&entry.path, entry).is_some() {
            return Err(&entry.path);
        }
    }
    Ok(index)
}

/// Verifies that the manifest's entries and the enumerated tree
/// entries agree in both directions (stamping specification §7
/// check 2).
pub fn run(
    manifest_entries: &[Entry],
    tree_entries: &[Entry],
) -> Result<(), Error> {
    let manifest_index = index_by_path(manifest_entries).map_err(|path| {
        Error::DuplicateManifestPath {
            path: path.to_vec(),
        }
    })?;
    let tree_index = index_by_path(tree_entries).map_err(|path| {
        Error::DuplicateTreePath {
            path: path.to_vec(),
        }
    })?;
    let mut disagreements = Vec::new();
    for (path, manifest_entry) in &manifest_index {
        match tree_index.get(path) {
            None => disagreements.push(Disagreement::MissingFromTree {
                path: path.to_vec(),
            }),
            Some(tree_entry) if tree_entry != manifest_entry => {
                disagreements.push(Disagreement::ConflictingContent {
                    manifest_entry: (*manifest_entry).clone(),
                    tree_entry: (**tree_entry).clone(),
                });
            }
            Some(_) => {}
        }
    }
    for path in tree_index.keys() {
        if !manifest_index.contains_key(path) {
            disagreements.push(Disagreement::MissingFromManifest {
                path: path.to_vec(),
            });
        }
    }
    if disagreements.is_empty() {
        Ok(())
    } else {
        Err(Error::Disagreements(disagreements))
    }
}

#[cfg(test)]
use super::manifest;

#[cfg(test)]
mod tests {
    use super::manifest::{FileMode, PayloadHashes};

    use super::*;

    fn entry_at(path: &[u8], fill_byte: u8) -> Entry {
        Entry {
            path: path.to_vec(),
            mode: FileMode::Regular,
            size: u64::from(fill_byte),
            content_hashes: PayloadHashes {
                sha256: [fill_byte; 32],
                sha3_256: [fill_byte.wrapping_add(1); 32],
            },
        }
    }

    #[test]
    fn identical_entry_sets_agree() {
        let manifest_side = vec![entry_at(b"a", 1), entry_at(b"b", 2)];
        let tree_side = vec![entry_at(b"b", 2), entry_at(b"a", 1)];
        assert_eq!(run(&manifest_side, &tree_side), Ok(()));
    }

    #[test]
    fn empty_sides_agree() {
        assert_eq!(run(&[], &[]), Ok(()));
    }

    #[test]
    fn a_manifest_entry_the_tree_lacks_is_reported() {
        let manifest_side = vec![entry_at(b"a", 1), entry_at(b"gone", 2)];
        let tree_side = vec![entry_at(b"a", 1)];
        assert_eq!(
            run(&manifest_side, &tree_side),
            Err(Error::Disagreements(vec![Disagreement::MissingFromTree {
                path: b"gone".to_vec(),
            }]))
        );
    }

    #[test]
    fn a_tree_file_the_manifest_lacks_is_reported() {
        let manifest_side = vec![entry_at(b"a", 1)];
        let tree_side = vec![entry_at(b"a", 1), entry_at(b"extra", 2)];
        assert_eq!(
            run(&manifest_side, &tree_side),
            Err(Error::Disagreements(vec![
                Disagreement::MissingFromManifest {
                    path: b"extra".to_vec(),
                }
            ]))
        );
    }

    #[test]
    fn a_hash_difference_on_one_family_is_a_conflict() {
        let manifest_entry = entry_at(b"a", 1);
        let mut tree_entry = entry_at(b"a", 1);
        tree_entry.content_hashes.sha3_256 = [9; 32];
        assert_eq!(
            run(
                std::slice::from_ref(&manifest_entry),
                std::slice::from_ref(&tree_entry)
            ),
            Err(Error::Disagreements(vec![
                Disagreement::ConflictingContent {
                    manifest_entry,
                    tree_entry,
                }
            ]))
        );
    }

    #[test]
    fn a_mode_difference_is_a_conflict() {
        let manifest_entry = entry_at(b"run.sh", 1);
        let mut tree_entry = entry_at(b"run.sh", 1);
        tree_entry.mode = FileMode::Executable;
        assert_eq!(
            run(
                std::slice::from_ref(&manifest_entry),
                std::slice::from_ref(&tree_entry)
            ),
            Err(Error::Disagreements(vec![
                Disagreement::ConflictingContent {
                    manifest_entry,
                    tree_entry,
                }
            ]))
        );
    }

    #[test]
    fn a_size_difference_is_a_conflict() {
        let manifest_entry = entry_at(b"a", 1);
        let mut tree_entry = entry_at(b"a", 1);
        tree_entry.size = 999;
        assert_eq!(
            run(
                std::slice::from_ref(&manifest_entry),
                std::slice::from_ref(&tree_entry)
            ),
            Err(Error::Disagreements(vec![
                Disagreement::ConflictingContent {
                    manifest_entry,
                    tree_entry,
                }
            ]))
        );
    }

    #[test]
    fn every_disagreeing_path_is_reported_not_just_the_first() {
        let manifest_side = vec![entry_at(b"only-manifest", 1)];
        let tree_side = vec![entry_at(b"only-tree", 2)];
        assert_eq!(
            run(&manifest_side, &tree_side),
            Err(Error::Disagreements(vec![
                Disagreement::MissingFromTree {
                    path: b"only-manifest".to_vec(),
                },
                Disagreement::MissingFromManifest {
                    path: b"only-tree".to_vec(),
                },
            ]))
        );
    }

    #[test]
    fn a_duplicate_manifest_path_refuses_the_comparison() {
        let manifest_side = vec![entry_at(b"a", 1), entry_at(b"a", 2)];
        let tree_side = vec![entry_at(b"a", 1)];
        assert_eq!(
            run(&manifest_side, &tree_side),
            Err(Error::DuplicateManifestPath {
                path: b"a".to_vec(),
            })
        );
    }

    #[test]
    fn a_duplicate_tree_path_refuses_the_comparison() {
        let manifest_side = vec![entry_at(b"a", 1)];
        let tree_side = vec![entry_at(b"a", 1), entry_at(b"a", 2)];
        assert_eq!(
            run(&manifest_side, &tree_side),
            Err(Error::DuplicateTreePath {
                path: b"a".to_vec(),
            })
        );
    }
}
