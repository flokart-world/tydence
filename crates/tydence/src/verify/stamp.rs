//! The stamp verdict (stamping specification §7): one entry point
//! running the four checks over one stamp commit's materials —
//! manifest syntax (check 1), bidirectional manifest/tree agreement
//! (check 2), full token verification (check 3), and renewal chain
//! linkage (check 4). The verdict is binary and fail-closed —
//! anything undecidable fails — and a stamp with several tokens
//! stands as long as one of them does.
//!
//! Everything is data-as-arguments: tree entries come from the
//! caller's snapshot enumeration, trust anchors and CRL snapshots
//! arrive as DER bytes, and bound artifacts are resolved by the
//! caller (they may come from outside the repository — epoch
//! rollover, §8). The canonical binding group order of §4.1 is
//! checkable through the binding module's edge derivation and order
//! check, but stands beside the verdict rather than inside it:
//! deciding canonicality needs the transitive binding relation, and
//! an edge that passes through a stamp outside the resolved set is
//! invisible to a verifier. Folding the check into the fail-closed
//! verdict would therefore wrongly fail the §6 skip-link scenario —
//! verifying a chain without its intermediate stamps — even though
//! its evidence is intact. Canonical order is a generation-time
//! property of the manifest text; the evidential weight is carried
//! by the hash bindings check 4 does verify.

use std::fmt;

use super::binding::{self, BoundStamp};
use super::manifest::{
    Entry, ManifestParseError, PayloadHashes, hash_payload, parse_manifest,
};
use super::token::{self, TokenSummary, TrustData};
use super::tree;
use super::x509::FailureCause;

/// One token file of the stamp under verification.
#[derive(Clone, Copy, Debug)]
pub struct SiteToken<'a> {
    /// The site name, as the token's file name records it.
    pub site: &'a str,
    pub bytes: &'a [u8],
}

/// A token that passed full verification.
#[derive(Clone, Debug)]
pub struct AcceptedToken {
    pub site: String,
    pub summary: TokenSummary,
}

/// A token that failed verification. A stamp survives rejected
/// tokens while at least one other token stands, but the rejection
/// is always reported.
#[derive(Debug)]
pub struct RejectedToken {
    pub site: String,
    pub cause: token::Error,
}

/// Everything the verification of one stamp commit consumes.
#[derive(Clone, Copy, Debug)]
pub struct StampInputs<'a> {
    /// The exact bytes of `.tydence/manifest`.
    pub manifest_bytes: &'a [u8],
    /// The snapshot enumeration of the stamp commit's tree.
    pub tree_entries: &'a [Entry],
    /// The stamp's token files.
    pub tokens: &'a [SiteToken<'a>],
    /// The bound stamps' artifact bytes, one per binding group in
    /// group order.
    pub bound_stamps: &'a [BoundStamp<'a>],
    pub trust: TrustData<'a>,
}

/// The outcome of a passed stamp verification.
#[derive(Debug)]
pub struct StampSummary {
    /// The hashes of the manifest bytes the accepted tokens vouch
    /// for, one per hash family the manifest format carries. Living
    /// only in a passed verdict, a reported digest is always a
    /// verified one — safe to transcribe into an external anchor.
    pub manifest_hashes: PayloadHashes,
    /// The tokens the stamp's validity rests on; never empty.
    pub accepted: Vec<AcceptedToken>,
    pub rejected: Vec<RejectedToken>,
}

#[derive(Debug)]
pub enum Error {
    /// The manifest bytes are not UTF-8 text.
    UnreadableManifest { source: FailureCause },
    /// Check 1: the manifest does not parse under a known format
    /// version.
    Manifest(ManifestParseError),
    /// Check 2 failed.
    Tree(tree::Error),
    /// Check 4 failed.
    Binding(binding::Error),
    /// The stamp claims no tokens at all, so there is nothing its
    /// validity could rest on.
    NoTokens,
    /// Check 3 failed for every token.
    AllTokensRejected(Vec<RejectedToken>),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableManifest { .. } => {
                write!(formatter, "the manifest bytes are not UTF-8")
            }
            Self::Manifest(cause) => {
                write!(formatter, "the manifest does not parse: {cause}")
            }
            Self::Tree(cause) => {
                write!(formatter, "manifest and tree disagree: {cause}")
            }
            Self::Binding(cause) => {
                write!(formatter, "the renewal chain does not link: {cause}")
            }
            Self::NoTokens => {
                write!(formatter, "the stamp carries no tokens")
            }
            Self::AllTokensRejected(rejections) => {
                write!(formatter, "every token failed verification:")?;
                for rejection in rejections {
                    write!(
                        formatter,
                        " [{}: {}]",
                        rejection.site, rejection.cause
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnreadableManifest { source } => Some(source.as_ref()),
            Self::Manifest(cause) => Some(cause),
            Self::Tree(cause) => Some(cause),
            Self::Binding(cause) => Some(cause),
            Self::NoTokens | Self::AllTokensRejected(_) => None,
        }
    }
}

/// Verifies one stamp commit's materials (stamping specification §7).
/// The verdict is the `Result` itself: `Ok` means the stamp passed
/// on at least one token, with every token's individual outcome
/// reported; any `Err` means the stamp fails.
pub fn run(inputs: &StampInputs<'_>) -> Result<StampSummary, Error> {
    let manifest_text =
        std::str::from_utf8(inputs.manifest_bytes).map_err(|source| {
            Error::UnreadableManifest {
                source: Box::new(source),
            }
        })?;
    let manifest = parse_manifest(manifest_text).map_err(Error::Manifest)?;
    tree::run(&manifest.entries, inputs.tree_entries).map_err(Error::Tree)?;
    binding::verify_binding_linkage(
        &manifest.binding_groups,
        inputs.bound_stamps,
    )
    .map_err(Error::Binding)?;
    if inputs.tokens.is_empty() {
        return Err(Error::NoTokens);
    }
    let basis = token::VerificationBasis {
        manifest_bytes: inputs.manifest_bytes,
        trust: inputs.trust,
    };
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for site_token in inputs.tokens {
        match token::verify_token(site_token.bytes, &basis) {
            Ok(summary) => accepted.push(AcceptedToken {
                site: site_token.site.to_string(),
                summary,
            }),
            Err(cause) => rejected.push(RejectedToken {
                site: site_token.site.to_string(),
                cause,
            }),
        }
    }
    if accepted.is_empty() {
        return Err(Error::AllTokensRejected(rejected));
    }
    Ok(StampSummary {
        manifest_hashes: hash_payload(inputs.manifest_bytes),
        accepted,
        rejected,
    })
}

#[cfg(test)]
use super::{manifest, test_pki};

#[cfg(test)]
mod tests {
    use super::manifest::{
        BindingGroup, FileMode, Manifest, PayloadHashes, hash_payload,
    };

    use super::*;

    const EMPTY_MANIFEST: &[u8] = b"tydence-manifest/v1\n";

    fn standard_setup() -> (test_pki::Authority, Vec<u8>, test_pki::TrustDers)
    {
        let authority = test_pki::standard_authority();
        let token_bytes = test_pki::encode_token(
            &test_pki::standard_token_parts(EMPTY_MANIFEST, &authority),
            &authority.tsa_key,
        );
        let bundle = test_pki::standard_trust_ders(&authority);
        (authority, token_bytes, bundle)
    }

    fn inputs_of<'a>(
        manifest_bytes: &'a [u8],
        tokens: &'a [SiteToken<'a>],
        bundle: &'a test_pki::TrustDers,
    ) -> StampInputs<'a> {
        StampInputs {
            manifest_bytes,
            tree_entries: &[],
            tokens,
            bound_stamps: &[],
            trust: TrustData {
                anchor_certificates: &bundle.anchors,
                companion_certificates: &bundle.companions,
                crls: &bundle.crls,
            },
        }
    }

    #[test]
    fn a_stamp_with_one_valid_token_passes() {
        let (_, token_bytes, bundle) = standard_setup();
        let tokens = [SiteToken {
            site: "testsite",
            bytes: &token_bytes,
        }];
        let summary = run(&inputs_of(EMPTY_MANIFEST, &tokens, &bundle))
            .expect("a stamp with a valid token passes");
        assert_eq!(summary.accepted.len(), 1);
        assert_eq!(summary.accepted[0].site, "testsite");
        assert!(summary.rejected.is_empty());
    }

    #[test]
    fn a_passed_verdict_reports_the_manifests_double_hash() {
        let (_, token_bytes, bundle) = standard_setup();
        let tokens = [SiteToken {
            site: "testsite",
            bytes: &token_bytes,
        }];
        let summary = run(&inputs_of(EMPTY_MANIFEST, &tokens, &bundle))
            .expect("a stamp with a valid token passes");
        // Expected digests computed outside this codebase, so a
        // hash_payload defect cannot cancel out on both sides.
        assert_eq!(
            summary.manifest_hashes.to_string(),
            "sha256:\
             e91b6fcd98da4986b125c5927b0e785413ec9a463d91a21c13ff58876e16a531 \
             sha3-256:\
             bfcef36df83d45b6117285c4f2c868961f2dbb2c7424de0301dca6c728c395d7"
        );
    }

    #[test]
    fn a_stamp_survives_a_rejected_token_beside_a_valid_one() {
        let (_, token_bytes, bundle) = standard_setup();
        let tokens = [
            SiteToken {
                site: "valid",
                bytes: &token_bytes,
            },
            SiteToken {
                site: "broken",
                bytes: b"not a token",
            },
        ];
        let summary = run(&inputs_of(EMPTY_MANIFEST, &tokens, &bundle))
            .expect("one valid token carries the stamp");
        assert_eq!(summary.accepted.len(), 1);
        assert_eq!(summary.rejected.len(), 1);
        assert_eq!(summary.rejected[0].site, "broken");
    }

    #[test]
    fn a_stamp_with_every_token_rejected_fails() {
        let (_, _, bundle) = standard_setup();
        let tokens = [SiteToken {
            site: "broken",
            bytes: b"not a token",
        }];
        let verdict = run(&inputs_of(EMPTY_MANIFEST, &tokens, &bundle));
        assert!(matches!(verdict, Err(Error::AllTokensRejected(_))));
    }

    #[test]
    fn a_stamp_without_tokens_fails() {
        let (_, _, bundle) = standard_setup();
        let verdict = run(&inputs_of(EMPTY_MANIFEST, &[], &bundle));
        assert!(matches!(verdict, Err(Error::NoTokens)));
    }

    #[test]
    fn a_tree_disagreement_fails_the_stamp() {
        let (_, token_bytes, bundle) = standard_setup();
        let tokens = [SiteToken {
            site: "testsite",
            bytes: &token_bytes,
        }];
        let extra_entry = Entry {
            path: b"unlisted".to_vec(),
            mode: FileMode::Regular,
            size: 1,
            content_hashes: PayloadHashes {
                sha256: [0; 32],
                sha3_256: [1; 32],
            },
        };
        let mut inputs = inputs_of(EMPTY_MANIFEST, &tokens, &bundle);
        let tree_entries = [extra_entry];
        inputs.tree_entries = &tree_entries;
        assert!(matches!(run(&inputs), Err(Error::Tree(_))));
    }

    #[test]
    fn an_unparseable_manifest_fails_the_stamp() {
        let (_, _, bundle) = standard_setup();
        let verdict = run(&inputs_of(b"nonsense\n", &[], &bundle));
        assert!(matches!(verdict, Err(Error::Manifest(_))));
    }

    #[test]
    fn a_manifest_that_is_not_utf8_fails_the_stamp() {
        let (_, _, bundle) = standard_setup();
        let verdict = run(&inputs_of(b"\xFF\xFE", &[], &bundle));
        assert!(matches!(verdict, Err(Error::UnreadableManifest { .. })));
    }

    #[test]
    fn a_binding_mismatch_fails_the_stamp() {
        let (_, _, bundle) = standard_setup();
        let bound_manifest = Manifest {
            parents: vec![],
            binding_groups: vec![BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: None,
                manifest_hashes: hash_payload(EMPTY_MANIFEST),
                tokens: vec![],
            }],
            entries: vec![],
        };
        let manifest_bytes = bound_manifest
            .serialize()
            .expect("well-formed fields serialize")
            .into_bytes();
        let bound_stamps = [BoundStamp {
            manifest_bytes: b"not the bound bytes",
            tokens: vec![],
        }];
        let mut inputs = inputs_of(&manifest_bytes, &[], &bundle);
        inputs.bound_stamps = &bound_stamps;
        assert!(matches!(run(&inputs), Err(Error::Binding(_))));
    }
}
