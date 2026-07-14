//! Configuration parsing: reads the `.tydence/config` text — site
//! definitions and the profiles selecting them — as specified by the
//! configuration manual (docs/user_manuals/config.md).

use std::collections::HashMap;
use std::fmt;
use std::mem;

use super::tsp::ImprintAlgorithm;

/// Why a configuration text was rejected. The parser fails closed
/// (configuration manual §2): anything it cannot positively accept
/// is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A directive name outside the format's vocabulary, or a
    /// spelling differing from the documented one.
    UnknownDirective { line_number: usize },
    /// A known directive whose arguments do not follow the grammar,
    /// including unknown modifiers and malformed values.
    MalformedDirective { line_number: usize },
    /// A directive at a position the structure does not allow it.
    MisplacedDirective { line_number: usize },
    /// A directive that restates what an earlier directive already
    /// established.
    DuplicateDirective { line_number: usize },
    /// A site or profile name outside the constraints of manual §4.
    InvalidName { line_number: usize },
    /// A profile selection naming a site no block defines.
    UnknownSite { line_number: usize },
    /// A site block that closed without both `URL` and `Imprint`.
    IncompleteSite { line_number: usize },
    /// A profile block that closed without a single selection.
    EmptyProfile { line_number: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownDirective { line_number } => {
                write!(formatter, "line {line_number}: unknown directive")
            }
            Error::MalformedDirective { line_number } => {
                write!(formatter, "line {line_number}: malformed directive")
            }
            Error::MisplacedDirective { line_number } => {
                write!(formatter, "line {line_number}: directive out of place")
            }
            Error::DuplicateDirective { line_number } => {
                write!(formatter, "line {line_number}: duplicate directive")
            }
            Error::InvalidName { line_number } => {
                write!(
                    formatter,
                    "line {line_number}: invalid site or profile name"
                )
            }
            Error::UnknownSite { line_number } => {
                write!(
                    formatter,
                    "line {line_number}: selection of an undefined site"
                )
            }
            Error::IncompleteSite { line_number } => {
                write!(
                    formatter,
                    "line {line_number}: site block missing URL or Imprint"
                )
            }
            Error::EmptyProfile { line_number } => {
                write!(
                    formatter,
                    "line {line_number}: profile with no site selections"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// One site definition: the (TSA, imprint algorithm) pair a name is
/// bound to (manual §3.1). The name itself is the key under which
/// the definition sits in [`Config::sites`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub url: String,
    pub imprint_algorithm: ImprintAlgorithm,
}

/// One `UseSite` line inside a profile: the selection of a defined
/// site together with its failure handling (manual §3.2, §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseSite {
    pub site_name: String,
    pub continues_on_error: bool,
}

/// One named selection of sites for a stamp to use (manual §3.2),
/// keyed by its name in [`Config::profiles`]. The selections keep
/// their written order so stamping walks them deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub selections: Vec<UseSite>,
}

/// The parsed configuration: site definitions and the profiles
/// grouping them, each keyed by name. Either map may be empty while
/// a repository's policy is still being set up — stamping, not
/// parsing, requires a usable profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub sites: HashMap<String, Site>,
    pub profiles: HashMap<String, Profile>,
}

// The conventional cap manual §4 places on names: not derived from
// a hard limit, only chosen well inside the nearest one (255 bytes
// for a `<name>.tsr` filename on common filesystems)
const MAX_NAME_LENGTH: usize = 64;

// Site names become token filenames and manifest fields, and
// profile names ride command lines; the shared constraint
// (manual §4) keeps every appearance trivially safe
fn is_valid_name(name: &str) -> bool {
    let name_bytes = name.as_bytes();
    let edges_are_alphanumeric = matches!(
        (name_bytes.first(), name_bytes.last()),
        (Some(first_byte), Some(last_byte))
            if first_byte.is_ascii_alphanumeric()
                && last_byte.is_ascii_alphanumeric()
    );
    name_bytes.len() <= MAX_NAME_LENGTH
        && edges_are_alphanumeric
        && name_bytes.iter().all(|name_byte| {
            name_byte.is_ascii_alphanumeric()
                || *name_byte == b'-'
                || *name_byte == b'_'
        })
}

// The scheme spelling is exact for the same reason directive
// spellings are (manual §2); the graphic-byte check rejects control
// characters the space-and-tab lexer cannot see — RFC 3986 URLs are
// ASCII to begin with
fn is_https_url(url: &str) -> bool {
    url.strip_prefix("https://")
        .is_some_and(|after_scheme| !after_scheme.is_empty())
        && url.bytes().all(|url_byte| url_byte.is_ascii_graphic())
}

/// The imprint vocabulary: the one place family names are tied to
/// their algorithms (manual §3.1).
const IMPRINTS: &[(&str, ImprintAlgorithm)] = &[
    ("sha256", ImprintAlgorithm::Sha256),
    ("sha384", ImprintAlgorithm::Sha384),
    ("sha512", ImprintAlgorithm::Sha512),
];

fn imprint_algorithm_of(family_name: &str) -> Option<ImprintAlgorithm> {
    IMPRINTS
        .iter()
        .find(|(known_family, _)| *known_family == family_name)
        .map(|(_, algorithm)| *algorithm)
}

/// A `Site` definition block read up to its current line.
struct PendingSite {
    line_number: usize,
    name: String,
    url: Option<String>,
    imprint_algorithm: Option<ImprintAlgorithm>,
}

/// A `Profile` block read up to its current line.
struct PendingProfile {
    line_number: usize,
    name: String,
    selections: Vec<UseSite>,
}

/// One `UseSite` argument and the line that made it, held until the
/// whole text is read: a definition may follow its uses (manual §3),
/// so resolution belongs to [`Builder::finish`].
struct SiteReference {
    site_name: String,
    line_number: usize,
}

/// Which block the reader stands in. Blocks close only when the
/// next block opens or the text ends; there is no closing directive
/// (manual §3).
enum Scope {
    TopLevel,
    SiteBlock(PendingSite),
    ProfileBlock(PendingProfile),
}

struct Builder {
    scope: Scope,
    sites: HashMap<String, Site>,
    profiles: HashMap<String, Profile>,
    unresolved_references: Vec<SiteReference>,
}

impl Builder {
    /// Closes the block the reader stands in, applying the checks
    /// only a complete block can answer.
    fn close_scope(&mut self) -> Result<(), Error> {
        match mem::replace(&mut self.scope, Scope::TopLevel) {
            Scope::TopLevel => Ok(()),
            Scope::SiteBlock(pending) => {
                let (Some(url), Some(imprint_algorithm)) =
                    (pending.url, pending.imprint_algorithm)
                else {
                    return Err(Error::IncompleteSite {
                        line_number: pending.line_number,
                    });
                };
                self.sites.insert(
                    pending.name,
                    Site {
                        url,
                        imprint_algorithm,
                    },
                );
                Ok(())
            }
            Scope::ProfileBlock(pending) => {
                if pending.selections.is_empty() {
                    return Err(Error::EmptyProfile {
                        line_number: pending.line_number,
                    });
                }
                self.profiles.insert(
                    pending.name,
                    Profile {
                        selections: pending.selections,
                    },
                );
                Ok(())
            }
        }
    }

    fn open_site(
        &mut self,
        arguments: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        // A definition takes exactly the name: modifiers belong to
        // selections, not definitions
        let [name] = arguments else {
            return Err(Error::MalformedDirective { line_number });
        };
        if !is_valid_name(name) {
            return Err(Error::InvalidName { line_number });
        }
        self.close_scope()?;
        if self.sites.contains_key(*name) {
            return Err(Error::DuplicateDirective { line_number });
        }
        self.scope = Scope::SiteBlock(PendingSite {
            line_number,
            name: name.to_string(),
            url: None,
            imprint_algorithm: None,
        });
        Ok(())
    }

    fn open_profile(
        &mut self,
        arguments: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        let [name] = arguments else {
            return Err(Error::MalformedDirective { line_number });
        };
        if !is_valid_name(name) {
            return Err(Error::InvalidName { line_number });
        }
        self.close_scope()?;
        if self.profiles.contains_key(*name) {
            return Err(Error::DuplicateDirective { line_number });
        }
        self.scope = Scope::ProfileBlock(PendingProfile {
            line_number,
            name: name.to_string(),
            selections: vec![],
        });
        Ok(())
    }

    fn read_selection(
        &mut self,
        arguments: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        let Scope::ProfileBlock(pending) = &mut self.scope else {
            return Err(Error::MisplacedDirective { line_number });
        };
        let (site_name, continues_on_error) = match arguments {
            [site_name] => (*site_name, false),
            [site_name, "ContinueOnError"] => (*site_name, true),
            // Anything else after the site name is an unknown
            // modifier
            _ => return Err(Error::MalformedDirective { line_number }),
        };
        let repeats_a_selection = pending
            .selections
            .iter()
            .any(|selection| selection.site_name == site_name);
        if repeats_a_selection {
            return Err(Error::DuplicateDirective { line_number });
        }
        pending.selections.push(UseSite {
            site_name: site_name.to_string(),
            continues_on_error,
        });
        self.unresolved_references.push(SiteReference {
            site_name: site_name.to_string(),
            line_number,
        });
        Ok(())
    }

    fn read_url(
        &mut self,
        arguments: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        let Scope::SiteBlock(pending) = &mut self.scope else {
            return Err(Error::MisplacedDirective { line_number });
        };
        let [url] = arguments else {
            return Err(Error::MalformedDirective { line_number });
        };
        if !is_https_url(url) {
            return Err(Error::MalformedDirective { line_number });
        }
        if pending.url.is_some() {
            return Err(Error::DuplicateDirective { line_number });
        }
        pending.url = Some(url.to_string());
        Ok(())
    }

    fn read_imprint(
        &mut self,
        arguments: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        let Scope::SiteBlock(pending) = &mut self.scope else {
            return Err(Error::MisplacedDirective { line_number });
        };
        let [family_name] = arguments else {
            return Err(Error::MalformedDirective { line_number });
        };
        let algorithm = imprint_algorithm_of(family_name)
            .ok_or(Error::MalformedDirective { line_number })?;
        if pending.imprint_algorithm.is_some() {
            return Err(Error::DuplicateDirective { line_number });
        }
        pending.imprint_algorithm = Some(algorithm);
        Ok(())
    }

    fn read_directive(
        &mut self,
        tokens: &[&str],
        line_number: usize,
    ) -> Result<(), Error> {
        let (directive_name, arguments) = tokens
            .split_first()
            .expect("blank lines are skipped before dispatch");
        // A comment opens only at the start of a line (manual §2),
        // so an argument beginning with `#` can only be a mistaken
        // attempt at one
        if arguments.iter().any(|argument| argument.starts_with('#')) {
            return Err(Error::MalformedDirective { line_number });
        }
        match *directive_name {
            "Site" => self.open_site(arguments, line_number),
            "URL" => self.read_url(arguments, line_number),
            "Imprint" => self.read_imprint(arguments, line_number),
            "Profile" => self.open_profile(arguments, line_number),
            "UseSite" => self.read_selection(arguments, line_number),
            _ => Err(Error::UnknownDirective { line_number }),
        }
    }

    fn finish(mut self) -> Result<Config, Error> {
        self.close_scope()?;
        // References resolve only now: a definition may follow its
        // uses, so no line-by-line check could have answered them
        for reference in &self.unresolved_references {
            if !self.sites.contains_key(&reference.site_name) {
                return Err(Error::UnknownSite {
                    line_number: reference.line_number,
                });
            }
        }
        Ok(Config {
            sites: self.sites,
            profiles: self.profiles,
        })
    }
}

/// Parses configuration text (docs/user_manuals/config.md) into a
/// [`Config`], failing closed: unknown directives or modifiers,
/// misplaced or duplicated directives, malformed values, and
/// dangling references are all rejected. An empty text is a valid,
/// empty configuration.
pub fn parse(config_text: &str) -> Result<Config, Error> {
    let mut builder = Builder {
        scope: Scope::TopLevel,
        sites: HashMap::new(),
        profiles: HashMap::new(),
        unresolved_references: vec![],
    };
    for (line_index, raw_line) in config_text.split('\n').enumerate() {
        // Lines end with LF; one trailing CR is tolerated so
        // checkouts that rewrite line endings still parse (§2)
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.trim_start_matches([' ', '\t']).starts_with('#') {
            continue;
        }
        // Only spaces and tabs separate arguments; any other
        // character rides along inside a token and fails whatever
        // check its directive applies
        let tokens: Vec<&str> = line
            .split([' ', '\t'])
            .filter(|token| !token.is_empty())
            .collect();
        if tokens.is_empty() {
            continue;
        }
        builder.read_directive(&tokens, line_index + 1)?;
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manual's example (§7); the fixture mirrors it verbatim.
    const MANUAL_EXAMPLE: &str =
        include_str!("../tests/fixtures/config/manual-example");

    // A complete definition to put the reader past whatever a test
    // needs as a valid prelude; it occupies lines 1 to 3
    const DEFINED_SITE: &str = "Site tsa\n\
                                URL https://tsa.example.jp/tsr\n\
                                Imprint sha256\n";

    #[test]
    fn empty_text_parses_to_the_empty_configuration() {
        let expected = Config {
            sites: HashMap::new(),
            profiles: HashMap::new(),
        };
        assert_eq!(parse(""), Ok(expected.clone()));
        assert_eq!(parse("\n \t\n"), Ok(expected.clone()));
        assert_eq!(
            parse("# only a comment\n  # indented one\n"),
            Ok(expected)
        );
    }

    #[test]
    fn the_manual_example_parses_to_its_model() {
        let expected = Config {
            sites: HashMap::from([
                (
                    "freetsa-sha512".to_string(),
                    Site {
                        url: "https://freetsa.org/tsr".to_string(),
                        imprint_algorithm: ImprintAlgorithm::Sha512,
                    },
                ),
                (
                    "accredited-sha384".to_string(),
                    Site {
                        url: "https://tsa.example.jp/tsr".to_string(),
                        imprint_algorithm: ImprintAlgorithm::Sha384,
                    },
                ),
            ]),
            profiles: HashMap::from([
                (
                    "light".to_string(),
                    Profile {
                        selections: vec![UseSite {
                            site_name: "freetsa-sha512".to_string(),
                            continues_on_error: false,
                        }],
                    },
                ),
                (
                    "annual".to_string(),
                    Profile {
                        selections: vec![
                            UseSite {
                                site_name: "accredited-sha384".to_string(),
                                continues_on_error: false,
                            },
                            UseSite {
                                site_name: "freetsa-sha512".to_string(),
                                continues_on_error: true,
                            },
                        ],
                    },
                ),
            ]),
        };
        assert_eq!(parse(MANUAL_EXAMPLE), Ok(expected));
    }

    #[test]
    fn sites_without_profiles_are_a_valid_configuration() {
        let expected = Config {
            sites: HashMap::from([(
                "tsa".to_string(),
                Site {
                    url: "https://tsa.example.jp/tsr".to_string(),
                    imprint_algorithm: ImprintAlgorithm::Sha256,
                },
            )]),
            profiles: HashMap::new(),
        };
        assert_eq!(parse(DEFINED_SITE), Ok(expected));
    }

    #[test]
    fn a_trailing_carriage_return_is_tolerated() {
        let crlf_text = DEFINED_SITE.replace('\n', "\r\n");
        assert_eq!(parse(&crlf_text), parse(DEFINED_SITE));
    }

    #[test]
    fn tabs_separate_arguments_but_other_whitespace_does_not() {
        let tabbed = "Site\ttsa\n\
                      \tURL\thttps://tsa.example.jp/tsr\n\
                      \tImprint\tsha256\n";
        assert_eq!(parse(tabbed), parse(DEFINED_SITE));
        // A no-break space is not a separator, so it welds the
        // directive name to its argument
        assert_eq!(
            parse("Site\u{00A0}tsa\n"),
            Err(Error::UnknownDirective { line_number: 1 })
        );
    }

    #[test]
    fn directive_spellings_are_exact() {
        assert_eq!(
            parse("site tsa\n"),
            Err(Error::UnknownDirective { line_number: 1 })
        );
        assert_eq!(
            parse("Site tsa\nUrl https://tsa.example.jp/tsr\n"),
            Err(Error::UnknownDirective { line_number: 2 })
        );
        assert_eq!(
            parse("Site tsa\nIMPRINT sha256\n"),
            Err(Error::UnknownDirective { line_number: 2 })
        );
    }

    #[test]
    fn a_version_directive_is_unknown_today() {
        // The retrofit path (manual §2) relies on this rejection
        assert_eq!(
            parse("Version 2\n"),
            Err(Error::UnknownDirective { line_number: 1 })
        );
    }

    #[test]
    fn a_comment_opens_only_at_the_start_of_a_line() {
        assert_eq!(
            parse("Site tsa # the accredited one\n"),
            Err(Error::MalformedDirective { line_number: 1 })
        );
        // A `#` inside an argument is just a character
        let fragment_url = "Site tsa\n\
                            URL https://tsa.example.jp/tsr#top\n\
                            Imprint sha256\n";
        let parsed = parse(fragment_url).expect("a fragment is no comment");
        assert_eq!(parsed.sites["tsa"].url, "https://tsa.example.jp/tsr#top");
    }

    #[test]
    fn a_site_definition_takes_exactly_one_name() {
        assert_eq!(
            parse("Site\n"),
            Err(Error::MalformedDirective { line_number: 1 })
        );
        // Modifiers belong to selections, not definitions
        assert_eq!(
            parse("Site tsa ContinueOnError\n"),
            Err(Error::MalformedDirective { line_number: 1 })
        );
    }

    #[test]
    fn url_and_imprint_outside_a_site_block_are_misplaced() {
        assert_eq!(
            parse("URL https://tsa.example.jp/tsr\n"),
            Err(Error::MisplacedDirective { line_number: 1 })
        );
        assert_eq!(
            parse("Imprint sha256\n"),
            Err(Error::MisplacedDirective { line_number: 1 })
        );
        let inside_profile =
            format!("{DEFINED_SITE}Profile p\nImprint sha256\n");
        assert_eq!(
            parse(&inside_profile),
            Err(Error::MisplacedDirective { line_number: 5 })
        );
    }

    #[test]
    fn a_site_block_missing_a_member_is_incomplete() {
        let missing_imprint = "Site tsa\nURL https://tsa.example.jp/tsr\n";
        assert_eq!(
            parse(missing_imprint),
            Err(Error::IncompleteSite { line_number: 1 })
        );
        let missing_url = "Site tsa\nImprint sha256\n";
        assert_eq!(
            parse(missing_url),
            Err(Error::IncompleteSite { line_number: 1 })
        );
        // The next block opener closes the dangling definition
        let closed_by_a_profile = "Site tsa\nProfile p\n";
        assert_eq!(
            parse(closed_by_a_profile),
            Err(Error::IncompleteSite { line_number: 1 })
        );
    }

    #[test]
    fn a_repeated_member_in_a_site_block_is_a_duplicate() {
        let doubled_url = "Site tsa\n\
                           URL https://tsa.example.jp/tsr\n\
                           URL https://other.example.jp/tsr\n";
        assert_eq!(
            parse(doubled_url),
            Err(Error::DuplicateDirective { line_number: 3 })
        );
        let doubled_imprint = "Site tsa\n\
                               URL https://tsa.example.jp/tsr\n\
                               Imprint sha256\n\
                               Imprint sha512\n";
        assert_eq!(
            parse(doubled_imprint),
            Err(Error::DuplicateDirective { line_number: 4 })
        );
    }

    #[test]
    fn a_non_https_url_is_malformed() {
        let schemes = [
            "http://tsa.example.jp/tsr",
            "ftp://tsa.example.jp/tsr",
            "HTTPS://tsa.example.jp/tsr",
            "https://",
        ];
        for scheme_case in schemes {
            let text = format!("Site tsa\nURL {scheme_case}\n");
            assert_eq!(
                parse(&text),
                Err(Error::MalformedDirective { line_number: 2 }),
                "accepted: {scheme_case}"
            );
        }
    }

    #[test]
    fn an_unknown_imprint_family_is_malformed() {
        let families = ["sha3-256", "sha1", "Sha256", "sha512/256"];
        for family_case in families {
            let text = format!("Site tsa\nImprint {family_case}\n");
            assert_eq!(
                parse(&text),
                Err(Error::MalformedDirective { line_number: 2 }),
                "accepted: {family_case}"
            );
        }
    }

    #[test]
    fn each_imprint_family_maps_to_its_algorithm() {
        let text = "Site s256\n\
                    URL https://tsa.example.jp/tsr\n\
                    Imprint sha256\n\
                    Site s384\n\
                    URL https://tsa.example.jp/tsr\n\
                    Imprint sha384\n\
                    Site s512\n\
                    URL https://tsa.example.jp/tsr\n\
                    Imprint sha512\n";
        let parsed = parse(text).expect("all three families are known");
        assert_eq!(
            parsed.sites["s256"].imprint_algorithm,
            ImprintAlgorithm::Sha256
        );
        assert_eq!(
            parsed.sites["s384"].imprint_algorithm,
            ImprintAlgorithm::Sha384
        );
        assert_eq!(
            parsed.sites["s512"].imprint_algorithm,
            ImprintAlgorithm::Sha512
        );
    }

    #[test]
    fn names_are_bounded_ascii_with_interior_punctuation_only() {
        let longest = "a".repeat(64);
        let valid = format!(
            "Site {longest}\n\
             URL https://tsa.example.jp/tsr\n\
             Imprint sha256\n"
        );
        let parsed =
            parse(&valid).expect("64 characters are within the bound");
        assert!(parsed.sites.contains_key(&longest));
        let invalid_names = [
            "a".repeat(65),
            "-tsa".to_string(),
            "tsa_".to_string(),
            "t$a".to_string(),
            "日本".to_string(),
        ];
        for invalid_name in invalid_names {
            let text = format!("Site {invalid_name}\n");
            assert_eq!(
                parse(&text),
                Err(Error::InvalidName { line_number: 1 }),
                "accepted: {invalid_name}"
            );
        }
        // Profile names share the constraint (manual §3.2)
        let invalid_profile = format!("{DEFINED_SITE}Profile -p\n");
        assert_eq!(
            parse(&invalid_profile),
            Err(Error::InvalidName { line_number: 4 })
        );
    }

    #[test]
    fn names_are_case_sensitive() {
        let distinct = "Site FreeTSA\n\
                        URL https://freetsa.org/tsr\n\
                        Imprint sha256\n\
                        Site freetsa\n\
                        URL https://freetsa.org/tsr\n\
                        Imprint sha256\n";
        let parsed = parse(distinct).expect("case distinguishes names");
        assert_eq!(parsed.sites.len(), 2);
        let cased_selection =
            format!("{DEFINED_SITE}Profile p\nUseSite TSA\n");
        assert_eq!(
            parse(&cased_selection),
            Err(Error::UnknownSite { line_number: 5 })
        );
    }

    #[test]
    fn a_site_definition_repeating_a_name_is_a_duplicate() {
        let text = format!("{DEFINED_SITE}Site tsa\n");
        assert_eq!(
            parse(&text),
            Err(Error::DuplicateDirective { line_number: 4 })
        );
    }

    #[test]
    fn a_profile_repeating_a_name_is_a_duplicate() {
        let text =
            format!("{DEFINED_SITE}Profile p\nUseSite tsa\nProfile p\n");
        assert_eq!(
            parse(&text),
            Err(Error::DuplicateDirective { line_number: 6 })
        );
    }

    #[test]
    fn a_profile_without_selections_is_empty() {
        let at_end_of_text = format!("{DEFINED_SITE}Profile p\n");
        assert_eq!(
            parse(&at_end_of_text),
            Err(Error::EmptyProfile { line_number: 4 })
        );
        let closed_by_the_next =
            format!("{DEFINED_SITE}Profile p\nProfile q\nUseSite tsa\n");
        assert_eq!(
            parse(&closed_by_the_next),
            Err(Error::EmptyProfile { line_number: 4 })
        );
    }

    #[test]
    fn a_selection_naming_an_undefined_site_is_unknown() {
        let text = format!("{DEFINED_SITE}Profile p\nUseSite elsewhere\n");
        assert_eq!(parse(&text), Err(Error::UnknownSite { line_number: 5 }));
    }

    #[test]
    fn a_selection_repeating_a_site_is_a_duplicate() {
        let text = format!(
            "{DEFINED_SITE}Profile p\n\
             UseSite tsa\n\
             UseSite tsa ContinueOnError\n"
        );
        assert_eq!(
            parse(&text),
            Err(Error::DuplicateDirective { line_number: 6 })
        );
    }

    #[test]
    fn an_unknown_modifier_is_malformed() {
        let unknown =
            format!("{DEFINED_SITE}Profile p\nUseSite tsa Sometimes\n");
        assert_eq!(
            parse(&unknown),
            Err(Error::MalformedDirective { line_number: 5 })
        );
        let doubled = format!(
            "{DEFINED_SITE}Profile p\n\
             UseSite tsa ContinueOnError ContinueOnError\n"
        );
        assert_eq!(
            parse(&doubled),
            Err(Error::MalformedDirective { line_number: 5 })
        );
    }

    #[test]
    fn a_selection_outside_a_profile_is_misplaced() {
        assert_eq!(
            parse("UseSite tsa\n"),
            Err(Error::MisplacedDirective { line_number: 1 })
        );
        assert_eq!(
            parse("Site tsa\nUseSite tsa\n"),
            Err(Error::MisplacedDirective { line_number: 2 })
        );
    }

    #[test]
    fn a_definition_may_follow_the_profile_using_it() {
        let uses_first = format!("Profile p\nUseSite tsa\n{DEFINED_SITE}");
        let expected = Config {
            sites: HashMap::from([(
                "tsa".to_string(),
                Site {
                    url: "https://tsa.example.jp/tsr".to_string(),
                    imprint_algorithm: ImprintAlgorithm::Sha256,
                },
            )]),
            profiles: HashMap::from([(
                "p".to_string(),
                Profile {
                    selections: vec![UseSite {
                        site_name: "tsa".to_string(),
                        continues_on_error: false,
                    }],
                },
            )]),
        };
        assert_eq!(parse(&uses_first), Ok(expected));
    }
}
