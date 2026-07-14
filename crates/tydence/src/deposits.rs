//! Working-tree LTV deposits (stamping specification §5): trust
//! material a stamp left beside the repository for the following
//! commit to seal. Enumerated — never derived by name — and shared
//! ground between the audit, which accepts deposits as CRL and
//! companion supply, and the staging that queues them for sealing.

use std::fmt;
use std::path::Path;

use super::layout::{
    CHAIN_FILE_SUFFIX, CRL_FILE_SUFFIX, LTV_CERTS_PATH, LTV_CRLS_PATH,
};

// Single spelling of the boxed cause type, as in the tsp module.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// Something under the deposit directories is not a regular
    /// `*<suffix>` record file; it is refused rather than skipped.
    Foreign { path: String },
    /// A deposit file could not be read.
    Unreadable { path: String, source: FailureCause },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Foreign { path } => write!(
                formatter,
                "{path:?} in the working tree is not laid out as an LTV \
                 record"
            ),
            Self::Unreadable { path, .. } => {
                write!(formatter, "cannot read the deposit at {path:?}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Foreign { .. } => None,
            Self::Unreadable { source, .. } => Some(source.as_ref()),
        }
    }
}

/// Which record layout a deposit follows (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositKind {
    /// A TSA certificate chain, `ltv/certs/*.cer`.
    Chain,
    /// A CRL snapshot, `ltv/crls/*.crl`.
    Crl,
}

/// One record layout of §3: where records of a kind live and how
/// their files are named.
#[derive(Debug)]
pub struct RecordLayout {
    pub kind: DepositKind,
    pub directory_path: &'static str,
    pub suffix: &'static str,
}

/// The §3 record layouts, one per deposit kind.
pub const RECORD_LAYOUTS: [RecordLayout; 2] = [
    RecordLayout {
        kind: DepositKind::Chain,
        directory_path: LTV_CERTS_PATH,
        suffix: CHAIN_FILE_SUFFIX,
    },
    RecordLayout {
        kind: DepositKind::Crl,
        directory_path: LTV_CRLS_PATH,
        suffix: CRL_FILE_SUFFIX,
    },
];

/// One deposit: its place in the repository layout and its PEM
/// bytes.
#[derive(Debug)]
pub struct DepositRecord {
    pub kind: DepositKind,
    pub repository_path: String,
    pub pem_bytes: Vec<u8>,
}

fn enumerate_directory(
    worktree: &Path,
    layout: &RecordLayout,
    records: &mut Vec<DepositRecord>,
) -> Result<(), Error> {
    let directory = worktree.join(layout.directory_path);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(source) => {
            return Err(Error::Unreadable {
                path: directory.display().to_string(),
                source: Box::new(source),
            });
        }
    };
    let mut paths: Vec<_> = entries
        .map(|maybe_entry| maybe_entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()
        .map_err(|source| Error::Unreadable {
            path: directory.display().to_string(),
            source: Box::new(source),
        })?;
    // Directory read order is filesystem-dependent; sorting keeps the
    // enumeration deterministic.
    paths.sort();
    for path in paths {
        let foreign_entry = || Error::Foreign {
            path: path.display().to_string(),
        };
        let file_name = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .filter(|file_name| file_name.ends_with(layout.suffix))
            .ok_or_else(foreign_entry)?
            .to_string();
        if !path.is_file() {
            return Err(foreign_entry());
        }
        let pem_bytes =
            std::fs::read(&path).map_err(|source| Error::Unreadable {
                path: path.display().to_string(),
                source: Box::new(source),
            })?;
        records.push(DepositRecord {
            kind: layout.kind,
            repository_path: format!("{}/{file_name}", layout.directory_path),
            pem_bytes,
        });
    }
    Ok(())
}

/// Enumerates every deposit the working tree holds. Absent
/// directories hold nothing.
pub fn enumerate(worktree: &Path) -> Result<Vec<DepositRecord>, Error> {
    let mut records = Vec::new();
    for layout in &RECORD_LAYOUTS {
        enumerate_directory(worktree, layout, &mut records)?;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn absent_deposit_directories_hold_nothing() {
        let worktree = tempfile::tempdir().expect("tempdir");
        let records =
            enumerate(worktree.path()).expect("an empty worktree enumerates");
        assert!(records.is_empty());
    }

    #[test]
    fn deposits_enumerate_with_their_kinds() {
        let worktree = tempfile::tempdir().expect("tempdir");
        for layout in &RECORD_LAYOUTS {
            fs::create_dir_all(worktree.path().join(layout.directory_path))
                .expect("directories are created");
        }
        fs::write(
            worktree.path().join(LTV_CERTS_PATH).join("a.cer"),
            b"chain",
        )
        .expect("the chain writes");
        fs::write(worktree.path().join(LTV_CRLS_PATH).join("b.crl"), b"crl")
            .expect("the CRL writes");
        let records =
            enumerate(worktree.path()).expect("the deposits enumerate");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, DepositKind::Chain);
        assert_eq!(
            records[0].repository_path,
            format!("{LTV_CERTS_PATH}/a.cer")
        );
        assert_eq!(records[1].kind, DepositKind::Crl);
    }

    #[test]
    fn a_foreign_suffix_fails_closed() {
        let worktree = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(worktree.path().join(LTV_CERTS_PATH))
            .expect("directories are created");
        fs::write(
            worktree.path().join(LTV_CERTS_PATH).join("notes.txt"),
            b"not a record",
        )
        .expect("the foreign file writes");
        let verdict = enumerate(worktree.path());
        assert!(matches!(verdict, Err(Error::Foreign { .. })));
    }

    #[test]
    fn a_subdirectory_among_records_fails_closed() {
        let worktree = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(
            worktree.path().join(LTV_CRLS_PATH).join("nested.crl"),
        )
        .expect("directories are created");
        let verdict = enumerate(worktree.path());
        assert!(matches!(verdict, Err(Error::Foreign { .. })));
    }
}
