use std::fmt;

use super::hex;
use super::path::encode_path;

/// Whether the value can stand as one token of a manifest line:
/// non-empty, printable ASCII, no whitespace. Serialization and
/// parsing share this predicate so that neither side accepts a
/// manifest the other would reject.
pub fn is_bare_token(field_value: &str) -> bool {
    !field_value.is_empty()
        && field_value
            .bytes()
            .all(|field_byte| field_byte.is_ascii_graphic())
}

/// A record field whose spelling the manifest grammar does not
/// admit for the field's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedField {
    pub field: &'static str,
    pub value: String,
}

impl fmt::Display for MalformedField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {:?} does not follow the field grammar",
            self.field, self.value
        )
    }
}

impl std::error::Error for MalformedField {}

fn parse_hash_field<const BYTE_COUNT: usize>(
    field_name: &'static str,
    hash_field: &str,
) -> Result<[u8; BYTE_COUNT], MalformedField> {
    let field_error = || MalformedField {
        field: field_name,
        value: hash_field.to_string(),
    };
    // The payload prefix of a hash field is the field's own name
    let hex_text = hash_field
        .strip_prefix(field_name)
        .and_then(|prefixed| prefixed.strip_prefix(':'))
        .ok_or_else(field_error)?;
    hex::decode(hex::LOWERCASE, hex_text).ok_or_else(field_error)
}

/// The hashes of one payload, one per hash family the manifest
/// format carries. Format v1 carries SHA-256 and SHA3-256; a later
/// format version adds families here (hash-tree renewal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHashes {
    pub sha256: [u8; 32],
    pub sha3_256: [u8; 32],
}

impl PayloadHashes {
    /// Renders the hash fields of a record payload: the exact form
    /// the `TryFrom` implementation below parses.
    fn serialize(&self) -> String {
        format!(
            "sha256:{} sha3-256:{}",
            hex::encode(hex::LOWERCASE, &self.sha256),
            hex::encode(hex::LOWERCASE, &self.sha3_256)
        )
    }
}

impl TryFrom<&[&str]> for PayloadHashes {
    type Error = MalformedField;

    /// Parses the hash fields of a record payload, given in the
    /// order the grammar writes them. Format v1 carries exactly two
    /// families; a later format version changes the expected set
    /// here, in one place.
    fn try_from(hash_fields: &[&str]) -> Result<Self, MalformedField> {
        match hash_fields {
            [sha256_field, sha3_field] => Ok(PayloadHashes {
                sha256: parse_hash_field("sha256", sha256_field)?,
                sha3_256: parse_hash_field("sha3-256", sha3_field)?,
            }),
            unexpected_fields => Err(MalformedField {
                field: "hashes",
                value: unexpected_fields.join(" "),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    Regular,
    Executable,
    Symlink,
}

// git tree-entry mode literals, adopted verbatim by the stamping
// specification §4.2
impl From<FileMode> for &'static str {
    fn from(mode: FileMode) -> &'static str {
        match mode {
            FileMode::Regular => "100644",
            FileMode::Executable => "100755",
            FileMode::Symlink => "120000",
        }
    }
}

const FILE_MODES: &[FileMode] =
    &[FileMode::Regular, FileMode::Executable, FileMode::Symlink];

impl TryFrom<&str> for FileMode {
    type Error = MalformedField;

    // The inverse of the literal conversion above: searching the
    // variants keeps the literal spellings written once
    fn try_from(mode_field: &str) -> Result<Self, MalformedField> {
        FILE_MODES
            .iter()
            .copied()
            .find(|mode| <&str>::from(*mode) == mode_field)
            .ok_or_else(|| MalformedField {
                field: "mode",
                value: mode_field.to_string(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The byte string git stores as the path, unencoded.
    pub path: Vec<u8>,
    pub mode: FileMode,
    pub size: u64,
    pub content_hashes: PayloadHashes,
}

/// The anchor specification a token follows. Unlike git file modes,
/// the label set is open by design — new anchor implementations
/// introduce labels without a manifest format change — so a label
/// this implementation does not know must still round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorSpec {
    Rfc3161,
    Unrecognized(String),
}

impl AnchorSpec {
    pub fn label(&self) -> &str {
        match self {
            AnchorSpec::Rfc3161 => "rfc3161",
            AnchorSpec::Unrecognized(label) => label,
        }
    }
}

impl TryFrom<&str> for AnchorSpec {
    type Error = MalformedField;

    fn try_from(spec_label: &str) -> Result<Self, MalformedField> {
        match spec_label {
            // Comparing against label() keeps the known spellings
            // written once
            known if known == AnchorSpec::Rfc3161.label() => {
                Ok(AnchorSpec::Rfc3161)
            }
            // Unknown labels round-trip by design (open label set),
            // but must still stand as a bare token
            unrecognized if is_bare_token(unrecognized) => {
                Ok(AnchorSpec::Unrecognized(unrecognized.to_string()))
            }
            unspellable => Err(MalformedField {
                field: "spec",
                value: unspellable.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastToken {
    pub spec: AnchorSpec,
    pub site: String,
    pub token_hashes: PayloadHashes,
}

/// One bound earlier stamp: its `predecessor` record when the stamp
/// lives outside this repository, the hashes of its manifest bytes,
/// and the hashes of its token files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingGroup {
    /// Position annotation locating the bound stamp; a git hex hash.
    pub commit: String,
    /// The unencoded designation of the predecessor repository, for
    /// a stamp bound across an epoch rollover.
    pub predecessor_origin: Option<Vec<u8>>,
    pub manifest_hashes: PayloadHashes,
    pub tokens: Vec<PastToken>,
}

/// A record field whose value cannot appear in a manifest line: the
/// grammar separates tokens with exactly one space, so a value with
/// whitespace or control bytes would read back differently than it
/// was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprintableField {
    pub field: &'static str,
    pub value: String,
}

impl fmt::Display for UnprintableField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {:?} is not a bare printable token",
            self.field, self.value
        )
    }
}

impl std::error::Error for UnprintableField {}

fn bare_token(
    field_value: &str,
    field_name: &'static str,
) -> Result<(), UnprintableField> {
    if is_bare_token(field_value) {
        Ok(())
    } else {
        Err(UnprintableField {
            field: field_name,
            value: field_value.to_string(),
        })
    }
}

fn entry_line(entry: &Entry) -> String {
    format!(
        "entry --path {} --mode {} --size {} -- {}",
        encode_path(&entry.path),
        <&str>::from(entry.mode),
        entry.size,
        entry.content_hashes.serialize()
    )
}

fn ordered_tokens(tokens: &[PastToken]) -> Vec<&PastToken> {
    let mut ordered: Vec<&PastToken> = tokens.iter().collect();
    ordered.sort_unstable_by(|left, right| {
        (left.spec.label(), &left.site).cmp(&(right.spec.label(), &right.site))
    });
    ordered
}

fn push_group_lines(
    output: &mut String,
    group: &BindingGroup,
) -> Result<(), UnprintableField> {
    bare_token(&group.commit, "commit")?;
    if let Some(origin) = &group.predecessor_origin {
        output.push_str(&format!(
            "predecessor --commit {} -- {}\n",
            group.commit,
            encode_path(origin)
        ));
    }
    output.push_str(&format!(
        "past-manifest --commit {} -- {}\n",
        group.commit,
        group.manifest_hashes.serialize()
    ));
    for token in ordered_tokens(&group.tokens) {
        bare_token(token.spec.label(), "spec")?;
        bare_token(&token.site, "site")?;
        output.push_str(&format!(
            "past-token --commit {} --spec {} --site {} -- {}\n",
            group.commit,
            token.spec.label(),
            token.site,
            token.token_hashes.serialize()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Position annotation: the stamp commit's parent hashes in git
    /// order. Empty for a root commit.
    pub parents: Vec<String>,
    /// Binding groups in their canonical order (stamping
    /// specification §4.1), as computed by
    /// [`order_binding_groups`](super::order::run).
    pub binding_groups: Vec<BindingGroup>,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Renders the canonical manifest text (stamping specification
    /// §4): token lines sorted within their group, entry lines
    /// sorted by whole-line byte order. Binding groups are emitted
    /// in the order given.
    pub fn serialize(&self) -> Result<String, UnprintableField> {
        let mut output = String::from("tydence-manifest/v1\n");
        if !self.parents.is_empty() {
            output.push_str("parents --");
            for parent in &self.parents {
                bare_token(parent, "parent commit")?;
                output.push(' ');
                output.push_str(parent);
            }
            output.push('\n');
        }
        for group in &self.binding_groups {
            push_group_lines(&mut output, group)?;
        }
        let mut entry_lines: Vec<String> =
            self.entries.iter().map(entry_line).collect();
        entry_lines.sort_unstable();
        for line in entry_lines {
            output.push_str(&line);
            output.push('\n');
        }
        Ok(output)
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

    // Expected hash text is built from a literal hex pair instead
    // of the production hex(), so a rendering bug cannot cancel out
    // on both sides of an assertion
    fn expected_hex(byte_pair: &str) -> String {
        byte_pair.repeat(32)
    }

    #[test]
    fn an_empty_manifest_is_just_the_header() {
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![],
        };
        assert_eq!(
            manifest.serialize(),
            Ok("tydence-manifest/v1\n".to_string())
        );
    }

    #[test]
    fn parents_are_kept_in_git_order() {
        let manifest = Manifest {
            parents: vec!["beef".to_string(), "cafe".to_string()],
            binding_groups: vec![],
            entries: vec![],
        };
        assert_eq!(
            manifest.serialize(),
            Ok("tydence-manifest/v1\nparents -- beef cafe\n".to_string())
        );
    }

    #[test]
    fn entry_lines_sort_by_encoded_bytes_not_raw_bytes() {
        // Raw bytes order "a b" (0x20) before "a!" (0x21), but the
        // encoded forms order "a!" before "a%20b" (0x21 < 0x25)
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![
                Entry {
                    path: b"a b".to_vec(),
                    mode: FileMode::Regular,
                    size: 1,
                    content_hashes: payload_hashes(0),
                },
                Entry {
                    path: b"a!".to_vec(),
                    mode: FileMode::Regular,
                    size: 2,
                    content_hashes: payload_hashes(2),
                },
            ],
        };
        let expected = format!(
            "tydence-manifest/v1\n\
             entry --path a! --mode 100644 --size 2 -- \
             sha256:{} sha3-256:{}\n\
             entry --path a%20b --mode 100644 --size 1 -- \
             sha256:{} sha3-256:{}\n",
            expected_hex("02"),
            expected_hex("03"),
            expected_hex("00"),
            expected_hex("01"),
        );
        assert_eq!(manifest.serialize(), Ok(expected));
    }

    #[test]
    fn a_binding_group_serializes_its_records_in_grammar_order() {
        let manifest = Manifest {
            parents: vec!["beef".to_string()],
            binding_groups: vec![BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: Some(b"old repo".to_vec()),
                manifest_hashes: payload_hashes(4),
                tokens: vec![PastToken {
                    spec: AnchorSpec::Rfc3161,
                    site: "freetsa".to_string(),
                    token_hashes: payload_hashes(6),
                }],
            }],
            entries: vec![],
        };
        let expected = format!(
            "tydence-manifest/v1\n\
             parents -- beef\n\
             predecessor --commit cafe -- old%20repo\n\
             past-manifest --commit cafe -- sha256:{} sha3-256:{}\n\
             past-token --commit cafe --spec rfc3161 --site freetsa \
             -- sha256:{} sha3-256:{}\n",
            expected_hex("04"),
            expected_hex("05"),
            expected_hex("06"),
            expected_hex("07"),
        );
        assert_eq!(manifest.serialize(), Ok(expected));
    }

    #[test]
    fn tokens_within_a_group_sort_by_spec_label_then_site() {
        let group = BindingGroup {
            commit: "cafe".to_string(),
            predecessor_origin: None,
            manifest_hashes: payload_hashes(0),
            tokens: vec![
                PastToken {
                    spec: AnchorSpec::Rfc3161,
                    site: "b-site".to_string(),
                    token_hashes: payload_hashes(2),
                },
                PastToken {
                    spec: AnchorSpec::Unrecognized("future".to_string()),
                    site: "z-site".to_string(),
                    token_hashes: payload_hashes(4),
                },
                PastToken {
                    spec: AnchorSpec::Rfc3161,
                    site: "a-site".to_string(),
                    token_hashes: payload_hashes(6),
                },
            ],
        };
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![group],
            entries: vec![],
        };
        let rendered =
            manifest.serialize().expect("well-formed fields serialize");
        let future_position = rendered
            .find("--spec future --site z-site")
            .expect("future token line must exist");
        let a_site_position = rendered
            .find("--spec rfc3161 --site a-site")
            .expect("a-site token line must exist");
        let b_site_position = rendered
            .find("--spec rfc3161 --site b-site")
            .expect("b-site token line must exist");
        assert!(future_position < a_site_position);
        assert!(a_site_position < b_site_position);
    }

    #[test]
    fn every_line_ends_with_a_newline_and_carries_no_edge_whitespace() {
        let manifest = Manifest {
            parents: vec!["beef".to_string()],
            binding_groups: vec![],
            entries: vec![Entry {
                path: b"README.md".to_vec(),
                mode: FileMode::Executable,
                size: 42,
                content_hashes: payload_hashes(8),
            }],
        };
        let rendered =
            manifest.serialize().expect("well-formed fields serialize");
        assert!(rendered.ends_with('\n'));
        for line in rendered.lines() {
            assert_eq!(line, line.trim());
            assert!(!line.contains("  "));
        }
    }

    #[test]
    fn executable_entries_carry_the_git_executable_mode() {
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![Entry {
                path: b"run.sh".to_vec(),
                mode: FileMode::Executable,
                size: 9,
                content_hashes: payload_hashes(0),
            }],
        };
        let expected = format!(
            "tydence-manifest/v1\n\
             entry --path run.sh --mode 100755 --size 9 -- \
             sha256:{} sha3-256:{}\n",
            expected_hex("00"),
            expected_hex("01"),
        );
        assert_eq!(manifest.serialize(), Ok(expected));
    }

    #[test]
    fn symlink_entries_carry_the_git_symlink_mode() {
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![],
            entries: vec![Entry {
                path: b"link".to_vec(),
                mode: FileMode::Symlink,
                size: 6,
                content_hashes: payload_hashes(0),
            }],
        };
        let expected = format!(
            "tydence-manifest/v1\n\
             entry --path link --mode 120000 --size 6 -- \
             sha256:{} sha3-256:{}\n",
            expected_hex("00"),
            expected_hex("01"),
        );
        assert_eq!(manifest.serialize(), Ok(expected));
    }

    #[test]
    fn a_site_name_with_whitespace_reports_the_field() {
        let manifest = Manifest {
            parents: vec![],
            binding_groups: vec![BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: None,
                manifest_hashes: payload_hashes(0),
                tokens: vec![PastToken {
                    spec: AnchorSpec::Rfc3161,
                    site: "free tsa".to_string(),
                    token_hashes: payload_hashes(2),
                }],
            }],
            entries: vec![],
        };
        assert_eq!(
            manifest.serialize(),
            Err(UnprintableField {
                field: "site",
                value: "free tsa".to_string(),
            })
        );
    }

    #[test]
    fn an_empty_parent_hash_reports_the_field() {
        let manifest = Manifest {
            parents: vec![String::new()],
            binding_groups: vec![],
            entries: vec![],
        };
        assert_eq!(
            manifest.serialize(),
            Err(UnprintableField {
                field: "parent commit",
                value: String::new(),
            })
        );
    }

    #[test]
    fn file_modes_parse_from_exactly_the_git_literals() {
        assert_eq!(FileMode::try_from("100644"), Ok(FileMode::Regular));
        assert_eq!(FileMode::try_from("100755"), Ok(FileMode::Executable));
        assert_eq!(FileMode::try_from("120000"), Ok(FileMode::Symlink));
        assert_eq!(
            FileMode::try_from("100600"),
            Err(MalformedField {
                field: "mode",
                value: "100600".to_string(),
            })
        );
    }

    #[test]
    fn anchor_specs_keep_unknown_labels_but_reject_unspellable_ones() {
        assert_eq!(AnchorSpec::try_from("rfc3161"), Ok(AnchorSpec::Rfc3161));
        assert_eq!(
            AnchorSpec::try_from("future"),
            Ok(AnchorSpec::Unrecognized("future".to_string()))
        );
        assert_eq!(
            AnchorSpec::try_from("bad\tlabel"),
            Err(MalformedField {
                field: "spec",
                value: "bad\tlabel".to_string(),
            })
        );
    }

    #[test]
    fn payload_hashes_parse_their_two_prefixed_fields() {
        let sha256_field = format!("sha256:{}", "0a".repeat(32));
        let sha3_field = format!("sha3-256:{}", "0b".repeat(32));
        assert_eq!(
            PayloadHashes::try_from(
                [sha256_field.as_str(), sha3_field.as_str()].as_slice()
            ),
            Ok(PayloadHashes {
                sha256: [0x0A; 32],
                sha3_256: [0x0B; 32],
            })
        );
        let swapped_fields = PayloadHashes::try_from(
            [sha3_field.as_str(), sha256_field.as_str()].as_slice(),
        );
        assert_eq!(
            swapped_fields,
            Err(MalformedField {
                field: "sha256",
                value: sha3_field.clone(),
            })
        );
    }

    #[test]
    fn payload_hashes_reject_an_unexpected_field_count() {
        let sha256_field = format!("sha256:{}", "0a".repeat(32));
        let missing_family =
            PayloadHashes::try_from([sha256_field.as_str()].as_slice());
        assert_eq!(
            missing_family,
            Err(MalformedField {
                field: "hashes",
                value: sha256_field,
            })
        );
    }
}
