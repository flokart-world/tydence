//! Verification check 4 (stamping specification §7): renewal chain
//! linkage, plus the canonical binding group order of §4.1.
//!
//! The `--commit` annotation on a binding group is only a locator:
//! the bound artifact bytes are caller-supplied and may equally come
//! from outside the repository (epoch rollover, specification §8).
//! Reproducing the recorded double hashes from those bytes is what
//! identifies them as the bound artifacts.

use std::fmt;

use super::manifest::{
    AnchorSpec, BindingEdge, BindingGroup, BindingOrderError, Manifest,
    hash_payload, order_binding_groups, parse_manifest,
};

/// One token file of a bound stamp, as resolved by the caller.
#[derive(Clone, Debug)]
pub struct BoundToken<'a> {
    pub spec: AnchorSpec,
    pub site: String,
    pub bytes: &'a [u8],
}

/// The artifact bytes of one bound stamp. The caller resolves one per
/// binding group, in group order. Resolved tokens the group's
/// `past-token` lines never claim are ignored: the manifest's claims
/// drive the check, not the supply.
#[derive(Clone, Debug)]
pub struct BoundStamp<'a> {
    pub manifest_bytes: &'a [u8],
    pub tokens: Vec<BoundToken<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The caller resolved a different number of stamps than the
    /// manifest binds; nothing can be paired up.
    StampCountMismatch { claimed: usize, resolved: usize },
    /// The resolved manifest bytes do not reproduce the group's
    /// `past-manifest` double hash.
    ManifestHashMismatch { group_index: usize },
    /// A claimed token has no resolved bytes.
    TokenUnresolved {
        group_index: usize,
        spec: AnchorSpec,
        site: String,
    },
    /// A claimed token matches more than one resolved entry, so the
    /// check cannot tell which bytes stand for it.
    TokenAmbiguous {
        group_index: usize,
        spec: AnchorSpec,
        site: String,
    },
    /// The resolved token bytes do not reproduce the `past-token`
    /// double hash.
    TokenHashMismatch {
        group_index: usize,
        spec: AnchorSpec,
        site: String,
    },
    /// A bound stamp's manifest could not be parsed, so no binding
    /// edges can be derived from it. The cause is carried as its
    /// rendering to keep this error comparable in full.
    BoundManifestUnreadable { group_index: usize, cause: String },
    /// The supplied binding relation does not order the groups.
    Unorderable(BindingOrderError),
    /// The groups are not written in the canonical order §4.1
    /// defines for the supplied binding relation.
    NonCanonicalOrder { first_divergence: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StampCountMismatch { claimed, resolved } => write!(
                formatter,
                "the manifest binds {claimed} stamp(s) but {resolved} \
                 were resolved"
            ),
            Self::ManifestHashMismatch { group_index } => write!(
                formatter,
                "binding group {group_index}: the resolved manifest bytes \
                 do not reproduce the past-manifest hashes"
            ),
            Self::TokenUnresolved {
                group_index,
                spec,
                site,
            } => write!(
                formatter,
                "binding group {group_index}: no bytes resolved for the \
                 {} token of site {site}",
                spec.label()
            ),
            Self::TokenAmbiguous {
                group_index,
                spec,
                site,
            } => write!(
                formatter,
                "binding group {group_index}: several resolved entries \
                 offer the {} token of site {site}",
                spec.label()
            ),
            Self::TokenHashMismatch {
                group_index,
                spec,
                site,
            } => write!(
                formatter,
                "binding group {group_index}: the resolved bytes for the \
                 {} token of site {site} do not reproduce the past-token \
                 hashes",
                spec.label()
            ),
            Self::BoundManifestUnreadable { group_index, cause } => write!(
                formatter,
                "binding group {group_index}: the bound manifest does not \
                 parse ({cause})"
            ),
            Self::Unorderable(cause) => write!(
                formatter,
                "the binding relation does not order the groups ({cause})"
            ),
            Self::NonCanonicalOrder { first_divergence } => write!(
                formatter,
                "the binding groups leave the canonical order at group \
                 {first_divergence}"
            ),
        }
    }
}

impl std::error::Error for Error {}

fn ensure_stamp_counts_match(
    groups: &[BindingGroup],
    resolved: &[BoundStamp<'_>],
) -> Result<(), Error> {
    if groups.len() == resolved.len() {
        Ok(())
    } else {
        Err(Error::StampCountMismatch {
            claimed: groups.len(),
            resolved: resolved.len(),
        })
    }
}

/// Verifies that every binding group's recorded double hashes are
/// reproduced by the caller-resolved artifact bytes (stamping
/// specification §7 check 4). `resolved` pairs with the groups by
/// position.
pub fn verify_binding_linkage(
    groups: &[BindingGroup],
    resolved: &[BoundStamp<'_>],
) -> Result<(), Error> {
    ensure_stamp_counts_match(groups, resolved)?;
    for (group_index, (group, stamp)) in
        groups.iter().zip(resolved).enumerate()
    {
        if hash_payload(stamp.manifest_bytes) != group.manifest_hashes {
            return Err(Error::ManifestHashMismatch { group_index });
        }
        for claimed in &group.tokens {
            let mut matches = stamp.tokens.iter().filter(|offered| {
                offered.spec == claimed.spec && offered.site == claimed.site
            });
            let first_match =
                matches.next().ok_or_else(|| Error::TokenUnresolved {
                    group_index,
                    spec: claimed.spec.clone(),
                    site: claimed.site.clone(),
                })?;
            if matches.next().is_some() {
                return Err(Error::TokenAmbiguous {
                    group_index,
                    spec: claimed.spec.clone(),
                    site: claimed.site.clone(),
                });
            }
            if hash_payload(first_match.bytes) != claimed.token_hashes {
                return Err(Error::TokenHashMismatch {
                    group_index,
                    spec: claimed.spec.clone(),
                    site: claimed.site.clone(),
                });
            }
        }
    }
    Ok(())
}

fn parse_bound_manifest(
    group_index: usize,
    manifest_bytes: &[u8],
) -> Result<Manifest, Error> {
    let unreadable =
        |cause: &dyn fmt::Display| Error::BoundManifestUnreadable {
            group_index,
            cause: cause.to_string(),
        };
    let manifest_text = std::str::from_utf8(manifest_bytes)
        .map_err(|utf8_error| unreadable(&utf8_error))?;
    parse_manifest(manifest_text)
        .map_err(|parse_error| unreadable(&parse_error))
}

/// Derives the binding edges among the groups that are visible in
/// the bound stamps' own manifests: group `i` binds group `j` when
/// `i`'s manifest carries a `past-manifest` whose hashes are `j`'s.
///
/// A transitive binding that only passes through stamps outside the
/// binding set is invisible to this derivation; callers that know
/// more of the chain can widen the edge list themselves before
/// checking the order.
pub fn derive_binding_edges(
    groups: &[BindingGroup],
    resolved: &[BoundStamp<'_>],
) -> Result<Vec<BindingEdge>, Error> {
    ensure_stamp_counts_match(groups, resolved)?;
    let mut edges = Vec::new();
    for (binder, stamp) in resolved.iter().enumerate() {
        let bound_manifest =
            parse_bound_manifest(binder, stamp.manifest_bytes)?;
        for (bound, bound_group) in groups.iter().enumerate() {
            let binds = binder != bound
                && bound_manifest.binding_groups.iter().any(|inner_group| {
                    inner_group.manifest_hashes == bound_group.manifest_hashes
                });
            if binds {
                edges.push(BindingEdge { binder, bound });
            }
        }
    }
    Ok(edges)
}

/// Verifies that the groups are written in the canonical order the
/// stamping specification §4.1 defines for the given binding
/// relation.
pub fn verify_binding_order(
    groups: &[BindingGroup],
    edges: &[BindingEdge],
) -> Result<(), Error> {
    let canonical = order_binding_groups(groups.to_vec(), edges)
        .map_err(Error::Unorderable)?;
    let first_divergence =
        groups
            .iter()
            .zip(&canonical)
            .position(|(actual, expected)| {
                actual.manifest_hashes != expected.manifest_hashes
            });
    match first_divergence {
        None => Ok(()),
        Some(position) => Err(Error::NonCanonicalOrder {
            first_divergence: position,
        }),
    }
}

#[cfg(test)]
use super::manifest;

#[cfg(test)]
mod tests {
    use super::manifest::{PastToken, PayloadHashes};

    use super::*;

    const FIRST_MANIFEST: &[u8] = b"tydence-manifest/v1\n";
    const FIRST_TOKEN: &[u8] = b"first token bytes";

    fn group_binding(
        manifest_bytes: &[u8],
        token_bytes: &[u8],
    ) -> BindingGroup {
        BindingGroup {
            commit: "cafe".to_string(),
            predecessor_origin: None,
            manifest_hashes: hash_payload(manifest_bytes),
            tokens: vec![PastToken {
                spec: AnchorSpec::Rfc3161,
                site: "freetsa".to_string(),
                token_hashes: hash_payload(token_bytes),
            }],
        }
    }

    fn stamp_offering<'a>(
        manifest_bytes: &'a [u8],
        token_bytes: &'a [u8],
    ) -> BoundStamp<'a> {
        BoundStamp {
            manifest_bytes,
            tokens: vec![BoundToken {
                spec: AnchorSpec::Rfc3161,
                site: "freetsa".to_string(),
                bytes: token_bytes,
            }],
        }
    }

    fn group_with_hashes(fill_byte: u8) -> BindingGroup {
        BindingGroup {
            commit: "cafe".to_string(),
            predecessor_origin: None,
            manifest_hashes: PayloadHashes {
                sha256: [fill_byte; 32],
                sha3_256: [fill_byte.wrapping_add(1); 32],
            },
            tokens: vec![],
        }
    }

    /// Serializes a manifest that binds exactly the given groups, for
    /// use as a bound stamp's manifest bytes.
    fn manifest_bytes_binding(bound_groups: &[BindingGroup]) -> Vec<u8> {
        let manifest = Manifest {
            parents: vec![],
            binding_groups: bound_groups.to_vec(),
            entries: vec![],
        };
        manifest
            .serialize()
            .expect("well-formed fields serialize")
            .into_bytes()
    }

    #[test]
    fn matching_artifact_bytes_link_the_chain() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let resolved = vec![stamp_offering(FIRST_MANIFEST, FIRST_TOKEN)];
        assert_eq!(verify_binding_linkage(&groups, &resolved), Ok(()));
    }

    #[test]
    fn an_unbound_manifest_needs_no_resolution() {
        assert_eq!(verify_binding_linkage(&[], &[]), Ok(()));
    }

    #[test]
    fn differing_manifest_bytes_break_the_chain() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let resolved = vec![stamp_offering(b"other bytes", FIRST_TOKEN)];
        assert_eq!(
            verify_binding_linkage(&groups, &resolved),
            Err(Error::ManifestHashMismatch { group_index: 0 })
        );
    }

    #[test]
    fn differing_token_bytes_break_the_chain() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let resolved = vec![stamp_offering(FIRST_MANIFEST, b"other bytes")];
        assert_eq!(
            verify_binding_linkage(&groups, &resolved),
            Err(Error::TokenHashMismatch {
                group_index: 0,
                spec: AnchorSpec::Rfc3161,
                site: "freetsa".to_string(),
            })
        );
    }

    #[test]
    fn a_missing_resolved_token_is_reported() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let mut resolved = vec![stamp_offering(FIRST_MANIFEST, FIRST_TOKEN)];
        resolved[0].tokens.clear();
        assert_eq!(
            verify_binding_linkage(&groups, &resolved),
            Err(Error::TokenUnresolved {
                group_index: 0,
                spec: AnchorSpec::Rfc3161,
                site: "freetsa".to_string(),
            })
        );
    }

    #[test]
    fn two_resolutions_of_one_token_are_ambiguous() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let mut resolved = vec![stamp_offering(FIRST_MANIFEST, FIRST_TOKEN)];
        let duplicate = resolved[0].tokens[0].clone();
        resolved[0].tokens.push(duplicate);
        assert_eq!(
            verify_binding_linkage(&groups, &resolved),
            Err(Error::TokenAmbiguous {
                group_index: 0,
                spec: AnchorSpec::Rfc3161,
                site: "freetsa".to_string(),
            })
        );
    }

    #[test]
    fn an_unclaimed_resolved_token_is_ignored() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        let mut resolved = vec![stamp_offering(FIRST_MANIFEST, FIRST_TOKEN)];
        resolved[0].tokens.push(BoundToken {
            spec: AnchorSpec::Rfc3161,
            site: "unclaimed".to_string(),
            bytes: b"whatever",
        });
        assert_eq!(verify_binding_linkage(&groups, &resolved), Ok(()));
    }

    #[test]
    fn a_stamp_count_mismatch_refuses_the_check() {
        let groups = vec![group_binding(FIRST_MANIFEST, FIRST_TOKEN)];
        assert_eq!(
            verify_binding_linkage(&groups, &[]),
            Err(Error::StampCountMismatch {
                claimed: 1,
                resolved: 0,
            })
        );
    }

    #[test]
    fn an_edge_is_derived_when_a_bound_manifest_binds_another_group() {
        // Group 0's stamp binds group 1's stamp: group 0's manifest
        // carries a past-manifest with group 1's hashes.
        let bound_group = group_binding(FIRST_MANIFEST, FIRST_TOKEN);
        let binder_manifest =
            manifest_bytes_binding(std::slice::from_ref(&bound_group));
        let groups = vec![
            BindingGroup {
                commit: "cafe".to_string(),
                predecessor_origin: None,
                manifest_hashes: hash_payload(&binder_manifest),
                tokens: vec![],
            },
            bound_group,
        ];
        let resolved = vec![
            BoundStamp {
                manifest_bytes: &binder_manifest,
                tokens: vec![],
            },
            BoundStamp {
                manifest_bytes: FIRST_MANIFEST,
                tokens: vec![],
            },
        ];
        assert_eq!(
            derive_binding_edges(&groups, &resolved),
            Ok(vec![BindingEdge {
                binder: 0,
                bound: 1,
            }])
        );
    }

    #[test]
    fn unrelated_bound_manifests_derive_no_edges() {
        let groups = vec![
            group_binding(FIRST_MANIFEST, FIRST_TOKEN),
            group_binding(b"tydence-manifest/v1\nparents -- beef\n", b"t"),
        ];
        let resolved = vec![
            BoundStamp {
                manifest_bytes: FIRST_MANIFEST,
                tokens: vec![],
            },
            BoundStamp {
                manifest_bytes: b"tydence-manifest/v1\nparents -- beef\n",
                tokens: vec![],
            },
        ];
        assert_eq!(derive_binding_edges(&groups, &resolved), Ok(vec![]));
    }

    #[test]
    fn an_unparseable_bound_manifest_refuses_edge_derivation() {
        let groups = vec![group_binding(b"not a manifest", FIRST_TOKEN)];
        let resolved = vec![BoundStamp {
            manifest_bytes: b"not a manifest",
            tokens: vec![],
        }];
        assert!(matches!(
            derive_binding_edges(&groups, &resolved),
            Err(Error::BoundManifestUnreadable { group_index: 0, .. })
        ));
    }

    #[test]
    fn payload_ordered_groups_are_canonical_without_edges() {
        let groups = vec![group_with_hashes(1), group_with_hashes(5)];
        assert_eq!(verify_binding_order(&groups, &[]), Ok(()));
    }

    #[test]
    fn payload_disordered_groups_are_refused_without_edges() {
        let groups = vec![group_with_hashes(5), group_with_hashes(1)];
        assert_eq!(
            verify_binding_order(&groups, &[]),
            Err(Error::NonCanonicalOrder {
                first_divergence: 0,
            })
        );
    }

    #[test]
    fn a_binder_may_precede_a_smaller_payload_it_binds() {
        let groups = vec![group_with_hashes(5), group_with_hashes(1)];
        let edges = [BindingEdge {
            binder: 0,
            bound: 1,
        }];
        assert_eq!(verify_binding_order(&groups, &edges), Ok(()));
    }

    #[test]
    fn a_cyclic_relation_is_unorderable() {
        let groups = vec![group_with_hashes(1), group_with_hashes(5)];
        let edges = [
            BindingEdge {
                binder: 0,
                bound: 1,
            },
            BindingEdge {
                binder: 1,
                bound: 0,
            },
        ];
        assert_eq!(
            verify_binding_order(&groups, &edges),
            Err(Error::Unorderable(BindingOrderError::Cycle))
        );
    }
}
