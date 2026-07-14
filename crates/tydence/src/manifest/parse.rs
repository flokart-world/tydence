use std::fmt;

use super::model::{
    AnchorSpec, BindingGroup, Entry, FileMode, Manifest, PastToken,
    PayloadHashes, is_bare_token,
};
use super::path::decode_path;

/// Why a manifest text was rejected. The parser fails closed
/// (stamping specification §4): anything it cannot positively
/// accept is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The header line is not a format version this implementation
    /// knows.
    UnsupportedFormat,
    /// The text does not end with a newline.
    MissingFinalNewline,
    /// A record name outside the format's fixed set.
    UnknownRecord { line_number: usize },
    /// A known record whose fields do not follow the grammar.
    MalformedRecord { line_number: usize },
    /// A record at a position the grammar does not allow it.
    MisplacedRecord { line_number: usize },
    /// A record that covers what an earlier record already covers.
    DuplicateRecord { line_number: usize },
    /// Well-formed records that do not re-serialize to the input
    /// byte for byte.
    NonCanonicalSerialization,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedFormat => {
                write!(formatter, "not a supported manifest format version")
            }
            Error::MissingFinalNewline => {
                write!(formatter, "the manifest does not end with a newline")
            }
            Error::UnknownRecord { line_number } => {
                write!(formatter, "line {line_number}: unknown record name")
            }
            Error::MalformedRecord { line_number } => {
                write!(formatter, "line {line_number}: malformed record")
            }
            Error::MisplacedRecord { line_number } => {
                write!(formatter, "line {line_number}: record out of order")
            }
            Error::DuplicateRecord { line_number } => {
                write!(formatter, "line {line_number}: duplicate coverage")
            }
            Error::NonCanonicalSerialization => {
                write!(formatter, "not the canonical serialization")
            }
        }
    }
}

impl std::error::Error for Error {}

// Splitting on single spaces still leaves tokens free to carry
// other control bytes, so every free-form field re-checks the same
// predicate serialization enforces
fn bare_field(field_value: &str) -> Option<String> {
    is_bare_token(field_value).then(|| field_value.to_string())
}

fn entry_size_from(size_field: &str) -> Option<u64> {
    // str::parse also accepts a leading `+` and leading zeros, which
    // have no canonical writing, so the shape is checked first;
    // parse() then only fails on u64 overflow
    let is_canonical_decimal = !size_field.is_empty()
        && size_field
            .bytes()
            .all(|size_byte| size_byte.is_ascii_digit())
        && (size_field == "0" || !size_field.starts_with('0'));
    if is_canonical_decimal {
        size_field.parse().ok()
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordKind {
    Parents,
    Predecessor,
    PastManifest,
    PastToken,
    Entry,
}

/// The record vocabulary: the one place record names are tied to
/// their kinds.
const RECORDS: &[(&str, RecordKind)] = &[
    ("parents", RecordKind::Parents),
    ("predecessor", RecordKind::Predecessor),
    ("past-manifest", RecordKind::PastManifest),
    ("past-token", RecordKind::PastToken),
    ("entry", RecordKind::Entry),
];

fn record_kind_of(record_name: &str) -> Option<RecordKind> {
    RECORDS
        .iter()
        .find(|(known_name, _)| *known_name == record_name)
        .map(|(_, kind)| *kind)
}

/// Where in the manifest the reader stands, named after what was
/// read last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Start,
    Parents,
    /// A `predecessor` announced a group whose `past-manifest` line
    /// must follow immediately.
    GroupAnnounced,
    Group,
    Entries,
}

/// The record grammar — `parents? (predecessor? past-manifest
/// past-token*)* entry*` — written as explicit arrows. A record
/// with no arrow out of the current section is misplaced.
const SECTION_ARROWS: &[(Section, RecordKind, Section)] = &[
    (Section::Start, RecordKind::Parents, Section::Parents),
    (
        Section::Start,
        RecordKind::Predecessor,
        Section::GroupAnnounced,
    ),
    (Section::Start, RecordKind::PastManifest, Section::Group),
    (Section::Start, RecordKind::Entry, Section::Entries),
    (
        Section::Parents,
        RecordKind::Predecessor,
        Section::GroupAnnounced,
    ),
    (Section::Parents, RecordKind::PastManifest, Section::Group),
    (Section::Parents, RecordKind::Entry, Section::Entries),
    (
        Section::GroupAnnounced,
        RecordKind::PastManifest,
        Section::Group,
    ),
    (
        Section::Group,
        RecordKind::Predecessor,
        Section::GroupAnnounced,
    ),
    (Section::Group, RecordKind::PastManifest, Section::Group),
    (Section::Group, RecordKind::PastToken, Section::Group),
    (Section::Group, RecordKind::Entry, Section::Entries),
    (Section::Entries, RecordKind::Entry, Section::Entries),
];

fn section_after(current: Section, incoming: RecordKind) -> Option<Section> {
    SECTION_ARROWS
        .iter()
        .find(|(from, on, _)| (*from, *on) == (current, incoming))
        .map(|(_, _, to)| *to)
}

/// A `predecessor` record read but not yet closed by the
/// `past-manifest` line of the group it opens.
struct PendingPredecessor {
    line_number: usize,
    commit: String,
    origin: Vec<u8>,
}

/// A `past-token` record together with the `--commit` annotation
/// tying it to its binding group.
struct TokenRecord {
    commit: String,
    token: PastToken,
}

struct Builder {
    section: Section,
    parents: Vec<String>,
    pending_predecessor: Option<PendingPredecessor>,
    binding_groups: Vec<BindingGroup>,
    entries: Vec<Entry>,
}

impl Builder {
    fn read_parents(
        &mut self,
        parent_hashes: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        // A root commit omits the line entirely instead of writing
        // an empty one
        if parent_hashes.is_empty() {
            return Err(Error::MalformedRecord { line_number });
        }
        for parent in parent_hashes {
            self.parents.push(
                bare_field(parent)
                    .ok_or(Error::MalformedRecord { line_number })?,
            );
        }
        Ok(())
    }

    fn read_past_manifest(
        &mut self,
        mut group: BindingGroup,
        line_number: usize,
    ) -> Result<(), Error> {
        // The canonical group order (§4.1) is keyed by the sha256
        // payload, so groups repeating one would leave the manifest
        // without a unique canonical writing
        let repeats_a_binding = self.binding_groups.iter().any(|bound| {
            bound.manifest_hashes.sha256 == group.manifest_hashes.sha256
        });
        if repeats_a_binding {
            return Err(Error::DuplicateRecord { line_number });
        }
        if let Some(announcement) = self.pending_predecessor.take() {
            if announcement.commit != group.commit {
                return Err(Error::MisplacedRecord { line_number });
            }
            group.predecessor_origin = Some(announcement.origin);
        }
        self.binding_groups.push(group);
        Ok(())
    }

    fn read_past_token(
        &mut self,
        record: TokenRecord,
        line_number: usize,
    ) -> Result<(), Error> {
        let current_group = self
            .binding_groups
            .last_mut()
            .expect("the Group section is only entered past a past-manifest");
        if record.commit != current_group.commit {
            return Err(Error::MisplacedRecord { line_number });
        }
        // The repository stores one token file per site (§3), so a
        // second line for the same file could only contradict the
        // first
        let repeats_a_token = current_group.tokens.iter().any(|bound| {
            bound.spec.label() == record.token.spec.label()
                && bound.site == record.token.site
        });
        if repeats_a_token {
            return Err(Error::DuplicateRecord { line_number });
        }
        current_group.tokens.push(record.token);
        Ok(())
    }

    fn read_entry(
        &mut self,
        entry: Entry,
        line_number: usize,
    ) -> Result<(), Error> {
        // Canonical entry order sorts same-path lines adjacently, so
        // comparing against the previous entry finds every duplicate
        // path the final canonicality check would not already reject
        let repeats_previous_path = self
            .entries
            .last()
            .is_some_and(|previous| previous.path == entry.path);
        if repeats_previous_path {
            return Err(Error::DuplicateRecord { line_number });
        }
        self.entries.push(entry);
        Ok(())
    }

    fn read_record(
        &mut self,
        record_line: &str,
        line_number: usize,
    ) -> Result<(), Error> {
        let malformed = Error::MalformedRecord { line_number };
        let tokens: Vec<&str> = record_line.split(' ').collect();
        let record_name = tokens
            .first()
            .expect("split always yields at least one token");
        let kind = record_kind_of(record_name)
            .ok_or(Error::UnknownRecord { line_number })?;
        let entered_section = section_after(self.section, kind)
            .ok_or(Error::MisplacedRecord { line_number })?;
        match (kind, tokens.as_slice()) {
            (RecordKind::Parents, [_, "--", parent_hashes @ ..]) => {
                self.read_parents(parent_hashes, line_number)
            }
            (
                RecordKind::Predecessor,
                [_, "--commit", commit, "--", origin],
            ) => {
                self.pending_predecessor = Some(PendingPredecessor {
                    line_number,
                    commit: bare_field(commit).ok_or(malformed)?,
                    origin: decode_path(origin).ok_or(malformed)?,
                });
                Ok(())
            }
            (
                RecordKind::PastManifest,
                [_, "--commit", commit, "--", hash_fields @ ..],
            ) => {
                let group = BindingGroup {
                    commit: bare_field(commit).ok_or(malformed)?,
                    predecessor_origin: None,
                    manifest_hashes: PayloadHashes::try_from(hash_fields)
                        .map_err(|_| malformed)?,
                    tokens: vec![],
                };
                self.read_past_manifest(group, line_number)
            }
            (
                RecordKind::PastToken,
                [
                    _,
                    "--commit",
                    commit,
                    "--spec",
                    spec_label,
                    "--site",
                    site,
                    "--",
                    hash_fields @ ..,
                ],
            ) => {
                let record = TokenRecord {
                    commit: bare_field(commit).ok_or(malformed)?,
                    token: PastToken {
                        spec: AnchorSpec::try_from(*spec_label)
                            .map_err(|_| malformed)?,
                        site: bare_field(site).ok_or(malformed)?,
                        token_hashes: PayloadHashes::try_from(hash_fields)
                            .map_err(|_| malformed)?,
                    },
                };
                self.read_past_token(record, line_number)
            }
            (
                RecordKind::Entry,
                [
                    _,
                    "--path",
                    path_field,
                    "--mode",
                    mode_field,
                    "--size",
                    size_field,
                    "--",
                    hash_fields @ ..,
                ],
            ) => {
                let entry = Entry {
                    path: decode_path(path_field).ok_or(malformed)?,
                    mode: FileMode::try_from(*mode_field)
                        .map_err(|_| malformed)?,
                    size: entry_size_from(size_field).ok_or(malformed)?,
                    content_hashes: PayloadHashes::try_from(hash_fields)
                        .map_err(|_| malformed)?,
                };
                self.read_entry(entry, line_number)
            }
            _ => Err(malformed),
        }?;
        // The section advances only once the record is accepted
        self.section = entered_section;
        Ok(())
    }

    fn finish(self) -> Result<Manifest, Error> {
        // A predecessor still pending here announced a group whose
        // past-manifest line never came
        if let Some(announcement) = &self.pending_predecessor {
            return Err(Error::MisplacedRecord {
                line_number: announcement.line_number,
            });
        }
        Ok(Manifest {
            parents: self.parents,
            binding_groups: self.binding_groups,
            entries: self.entries,
        })
    }
}

/// Parses canonical manifest text (stamping specification §4) back
/// into a [`Manifest`], failing closed: unknown format versions,
/// unknown record or field names, grammar violations, and any text
/// that is not the canonical serialization of what it describes are
/// all rejected. Group order canonicality is the one property left
/// unchecked — it depends on the binding relations inside the bound
/// stamps' own manifests, which only verification sees.
pub fn run(manifest_text: &str) -> Result<Manifest, Error> {
    let record_text = manifest_text
        .strip_suffix('\n')
        .ok_or(Error::MissingFinalNewline)?;
    let mut lines = record_text.split('\n');
    let header = lines.next().expect("split always yields at least one line");
    if header != "tydence-manifest/v1" {
        return Err(Error::UnsupportedFormat);
    }
    let mut builder = Builder {
        section: Section::Start,
        parents: vec![],
        pending_predecessor: None,
        binding_groups: vec![],
        entries: vec![],
    };
    for (record_index, record_line) in lines.enumerate() {
        // The header occupies line 1, so records start at line 2
        builder.read_record(record_line, record_index + 2)?;
    }
    let manifest = builder.finish()?;
    // Every field was validated while parsing, so serialization
    // cannot fail here; mapping instead of unwrapping keeps the
    // library's no-panic guarantee either way
    let canonical_text = manifest
        .serialize()
        .map_err(|_| Error::NonCanonicalSerialization)?;
    if canonical_text == manifest_text {
        Ok(manifest)
    } else {
        Err(Error::NonCanonicalSerialization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_hashes(fill_byte: u8) -> PayloadHashes {
        PayloadHashes {
            sha256: [fill_byte; 32],
            sha3_256: [fill_byte + 1; 32],
        }
    }

    // Payload text is built from literal hex pairs instead of the
    // production rendering, so a bug there cannot cancel out on
    // both sides of an assertion
    fn payload_fields(sha256_pair: &str, sha3_pair: &str) -> String {
        format!(
            "sha256:{} sha3-256:{}",
            sha256_pair.repeat(32),
            sha3_pair.repeat(32)
        )
    }

    #[test]
    fn the_empty_manifest_parses_to_the_empty_model() {
        let expected = Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![],
        };
        assert_eq!(run("tydence-manifest/v1\n"), Ok(expected));
    }

    #[test]
    fn a_golden_manifest_parses_to_its_model() {
        let text = format!(
            "tydence-manifest/v1\n\
             parents -- beef\n\
             predecessor --commit 1111 -- old%20repo\n\
             past-manifest --commit 1111 -- {}\n\
             past-token --commit 1111 --spec rfc3161 --site freetsa -- {}\n\
             entry --path a%20b --mode 100755 --size 7 -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
            payload_fields("30", "31"),
        );
        let expected = Manifest {
            parents: vec!["beef".to_string()],
            binding_groups: vec![BindingGroup {
                commit: "1111".to_string(),
                predecessor_origin: Some(b"old repo".to_vec()),
                manifest_hashes: payload_hashes(0x10),
                tokens: vec![PastToken {
                    spec: AnchorSpec::Rfc3161,
                    site: "freetsa".to_string(),
                    token_hashes: payload_hashes(0x20),
                }],
            }],
            entries: vec![Entry {
                path: b"a b".to_vec(),
                mode: FileMode::Executable,
                size: 7,
                content_hashes: payload_hashes(0x30),
            }],
        };
        assert_eq!(run(&text), Ok(expected));
    }

    #[test]
    fn a_full_manifest_round_trips_through_serialize_and_parse() {
        let manifest = Manifest {
            parents: vec!["beef".to_string(), "cafe".to_string()],
            binding_groups: vec![
                BindingGroup {
                    commit: "1111".to_string(),
                    predecessor_origin: Some(b"old repo".to_vec()),
                    manifest_hashes: payload_hashes(0x10),
                    tokens: vec![
                        PastToken {
                            spec: AnchorSpec::Unrecognized(
                                "future".to_string(),
                            ),
                            site: "z-site".to_string(),
                            token_hashes: payload_hashes(0x20),
                        },
                        PastToken {
                            spec: AnchorSpec::Rfc3161,
                            site: "a-site".to_string(),
                            token_hashes: payload_hashes(0x30),
                        },
                        PastToken {
                            spec: AnchorSpec::Rfc3161,
                            site: "b-site".to_string(),
                            token_hashes: payload_hashes(0x40),
                        },
                    ],
                },
                BindingGroup {
                    commit: "2222".to_string(),
                    predecessor_origin: None,
                    manifest_hashes: payload_hashes(0x50),
                    tokens: vec![PastToken {
                        spec: AnchorSpec::Rfc3161,
                        site: "freetsa".to_string(),
                        token_hashes: payload_hashes(0x60),
                    }],
                },
            ],
            entries: vec![
                Entry {
                    path: b"README.md".to_vec(),
                    mode: FileMode::Regular,
                    size: 100,
                    content_hashes: payload_hashes(0x70),
                },
                Entry {
                    path: b"a b".to_vec(),
                    mode: FileMode::Regular,
                    size: 0,
                    content_hashes: payload_hashes(0x80),
                },
                Entry {
                    path: b"link".to_vec(),
                    mode: FileMode::Symlink,
                    size: 6,
                    content_hashes: payload_hashes(0x90),
                },
                Entry {
                    path: b"run.sh".to_vec(),
                    mode: FileMode::Executable,
                    size: 9,
                    content_hashes: payload_hashes(0xA0),
                },
            ],
        };
        let text = manifest.serialize().expect("well-formed fields serialize");
        assert_eq!(run(&text), Ok(manifest));
    }

    #[test]
    fn an_unknown_format_version_is_rejected() {
        assert_eq!(
            run("tydence-manifest/v2\n"),
            Err(Error::UnsupportedFormat)
        );
        assert_eq!(run("some other file\n"), Err(Error::UnsupportedFormat));
    }

    #[test]
    fn text_without_a_final_newline_is_rejected() {
        assert_eq!(
            run("tydence-manifest/v1"),
            Err(Error::MissingFinalNewline)
        );
        assert_eq!(run(""), Err(Error::MissingFinalNewline));
    }

    #[test]
    fn an_unknown_record_name_is_rejected_with_its_line() {
        let text = "tydence-manifest/v1\nsignature -- 00\n";
        assert_eq!(run(text), Err(Error::UnknownRecord { line_number: 2 }));
    }

    #[test]
    fn an_empty_line_is_rejected() {
        let text = "tydence-manifest/v1\n\n";
        assert_eq!(run(text), Err(Error::UnknownRecord { line_number: 2 }));
    }

    #[test]
    fn a_known_record_with_reordered_fields_is_malformed() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --mode 100644 --path a --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MalformedRecord { line_number: 2 }));
    }

    #[test]
    fn an_empty_parents_line_is_malformed() {
        let text = "tydence-manifest/v1\nparents --\n";
        assert_eq!(run(text), Err(Error::MalformedRecord { line_number: 2 }));
    }

    #[test]
    fn doubled_or_trailing_spaces_are_malformed() {
        let doubled = "tydence-manifest/v1\nparents --  beef\n";
        assert_eq!(
            run(doubled),
            Err(Error::MalformedRecord { line_number: 2 })
        );
        let trailing = "tydence-manifest/v1\nparents -- beef \n";
        assert_eq!(
            run(trailing),
            Err(Error::MalformedRecord { line_number: 2 })
        );
    }

    #[test]
    fn uppercase_or_short_hash_hex_is_malformed() {
        let uppercase = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- sha256:{} sha3-256:{}\n",
            "AB".repeat(32),
            "11".repeat(32),
        );
        assert_eq!(
            run(&uppercase),
            Err(Error::MalformedRecord { line_number: 2 })
        );
        let short = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- sha256:{} sha3-256:{}\n",
            "ab".repeat(31),
            "11".repeat(32),
        );
        assert_eq!(
            run(&short),
            Err(Error::MalformedRecord { line_number: 2 })
        );
    }

    #[test]
    fn a_non_git_mode_is_malformed() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path a --mode 100600 --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MalformedRecord { line_number: 2 }));
    }

    #[test]
    fn a_size_with_no_canonical_writing_is_malformed() {
        let leading_zero = format!(
            "tydence-manifest/v1\n\
             entry --path a --mode 100644 --size 007 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(
            run(&leading_zero),
            Err(Error::MalformedRecord { line_number: 2 })
        );
        let signed = format!(
            "tydence-manifest/v1\n\
             entry --path a --mode 100644 --size +7 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(
            run(&signed),
            Err(Error::MalformedRecord { line_number: 2 })
        );
    }

    #[test]
    fn a_lowercase_path_escape_is_malformed() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path a%2fb --mode 100644 --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MalformedRecord { line_number: 2 }));
    }

    #[test]
    fn parents_after_a_binding_group_are_misplaced() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- {}\n\
             parents -- beef\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MisplacedRecord { line_number: 3 }));
    }

    #[test]
    fn a_second_parents_line_is_misplaced() {
        let text = "tydence-manifest/v1\n\
                    parents -- beef\n\
                    parents -- cafe\n";
        assert_eq!(run(text), Err(Error::MisplacedRecord { line_number: 3 }));
    }

    #[test]
    fn a_past_token_before_any_past_manifest_is_misplaced() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-token --commit 1111 --spec rfc3161 --site freetsa \
             -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MisplacedRecord { line_number: 2 }));
    }

    #[test]
    fn a_past_token_outside_its_group_commit_is_misplaced() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- {}\n\
             past-token --commit 2222 --spec rfc3161 --site freetsa \
             -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
        );
        assert_eq!(run(&text), Err(Error::MisplacedRecord { line_number: 3 }));
    }

    #[test]
    fn a_predecessor_not_closed_by_its_past_manifest_is_misplaced() {
        let doubled = format!(
            "tydence-manifest/v1\n\
             predecessor --commit 1111 -- somewhere\n\
             predecessor --commit 2222 -- elsewhere\n\
             past-manifest --commit 2222 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(
            run(&doubled),
            Err(Error::MisplacedRecord { line_number: 3 })
        );
        let interrupted = format!(
            "tydence-manifest/v1\n\
             predecessor --commit 1111 -- somewhere\n\
             entry --path a --mode 100644 --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(
            run(&interrupted),
            Err(Error::MisplacedRecord { line_number: 3 })
        );
        let dangling = "tydence-manifest/v1\n\
                        predecessor --commit 1111 -- somewhere\n";
        assert_eq!(
            run(dangling),
            Err(Error::MisplacedRecord { line_number: 2 })
        );
    }

    #[test]
    fn a_predecessor_commit_differing_from_its_group_is_misplaced() {
        let text = format!(
            "tydence-manifest/v1\n\
             predecessor --commit 1111 -- somewhere\n\
             past-manifest --commit 2222 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::MisplacedRecord { line_number: 3 }));
    }

    #[test]
    fn binding_records_after_the_first_entry_are_misplaced() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path a --mode 100644 --size 1 -- {}\n\
             past-manifest --commit 1111 -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
        );
        assert_eq!(run(&text), Err(Error::MisplacedRecord { line_number: 3 }));
    }

    #[test]
    fn groups_repeating_a_sha256_payload_are_duplicates() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- {}\n\
             past-manifest --commit 2222 -- {}\n",
            payload_fields("10", "11"),
            payload_fields("10", "21"),
        );
        assert_eq!(run(&text), Err(Error::DuplicateRecord { line_number: 3 }));
    }

    #[test]
    fn token_lines_repeating_a_spec_and_site_are_duplicates() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- {}\n\
             past-token --commit 1111 --spec rfc3161 --site freetsa \
             -- {}\n\
             past-token --commit 1111 --spec rfc3161 --site freetsa \
             -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
            payload_fields("30", "31"),
        );
        assert_eq!(run(&text), Err(Error::DuplicateRecord { line_number: 4 }));
    }

    #[test]
    fn entries_repeating_a_path_are_duplicates() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path a --mode 100644 --size 1 -- {}\n\
             entry --path a --mode 100755 --size 1 -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
        );
        assert_eq!(run(&text), Err(Error::DuplicateRecord { line_number: 3 }));
    }

    #[test]
    fn unsorted_entries_are_not_canonical() {
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path b --mode 100644 --size 1 -- {}\n\
             entry --path a --mode 100644 --size 1 -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
        );
        assert_eq!(run(&text), Err(Error::NonCanonicalSerialization));
    }

    #[test]
    fn unsorted_tokens_within_a_group_are_not_canonical() {
        let text = format!(
            "tydence-manifest/v1\n\
             past-manifest --commit 1111 -- {}\n\
             past-token --commit 1111 --spec rfc3161 --site b-site \
             -- {}\n\
             past-token --commit 1111 --spec rfc3161 --site a-site \
             -- {}\n",
            payload_fields("10", "11"),
            payload_fields("20", "21"),
            payload_fields("30", "31"),
        );
        assert_eq!(run(&text), Err(Error::NonCanonicalSerialization));
    }

    #[test]
    fn an_over_escaped_path_is_not_canonical() {
        // %61 decodes to 'a', which the canonical encoding keeps raw
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path %61 --mode 100644 --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::NonCanonicalSerialization));
    }

    #[test]
    fn a_raw_character_the_format_escapes_is_not_canonical() {
        // A raw ZWJ survives space-splitting but canonically encodes
        // as %E2%80%8D
        let text = format!(
            "tydence-manifest/v1\n\
             entry --path a\u{200D}b --mode 100644 --size 1 -- {}\n",
            payload_fields("10", "11"),
        );
        assert_eq!(run(&text), Err(Error::NonCanonicalSerialization));
    }
}
