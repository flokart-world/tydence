use std::fmt;

use super::model::BindingGroup;

/// `groups[binder]`'s stamp binds `groups[bound]`'s stamp — that
/// is, the binder's manifest carries the bound stamp's hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingEdge {
    pub binder: usize,
    pub bound: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEdge(BindingEdge),
    Cycle,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidEdge(edge) => write!(
                formatter,
                "binding edge {edge:?} does not name two distinct groups"
            ),
            Error::Cycle => {
                write!(formatter, "the binding relation contains a cycle")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Reorders binding groups into the canonical order (stamping
/// specification §4.1): the lexicographically smallest, by
/// `past-manifest` sha256 payload bytes, of all orderings in which
/// every binder precedes the stamps it binds. Listing the edges
/// directly or transitively closed makes no difference.
pub fn run(
    groups: Vec<BindingGroup>,
    edges: &[BindingEdge],
) -> Result<Vec<BindingGroup>, Error> {
    for edge in edges {
        let names_two_distinct_groups = edge.binder < groups.len()
            && edge.bound < groups.len()
            && edge.binder != edge.bound;
        if !names_two_distinct_groups {
            return Err(Error::InvalidEdge(*edge));
        }
    }
    // Greedily emitting the smallest payload among the groups no
    // unemitted group binds yields exactly the lexicographic
    // minimum the specification defines
    let mut group_slots: Vec<Option<BindingGroup>> =
        groups.into_iter().map(Some).collect();
    let mut ordered = Vec::with_capacity(group_slots.len());
    while ordered.len() < group_slots.len() {
        let emittable = (0..group_slots.len())
            .filter(|slot_index| group_slots[*slot_index].is_some())
            .filter(|slot_index| {
                edges.iter().all(|edge| {
                    edge.bound != *slot_index
                        || group_slots[edge.binder].is_none()
                })
            });
        let Some(next_index) = emittable.min_by_key(|slot_index| {
            group_slots[*slot_index]
                .as_ref()
                .expect("filtered to occupied slots")
                .manifest_hashes
                .sha256
        }) else {
            return Err(Error::Cycle);
        };
        ordered.push(
            group_slots[next_index]
                .take()
                .expect("selected from occupied slots"),
        );
    }
    Ok(ordered)
}

#[cfg(test)]
use super::model;

#[cfg(test)]
mod tests {
    use super::model::PayloadHashes;
    use super::*;

    fn group_with_key(key: u8) -> BindingGroup {
        BindingGroup {
            commit: "cafe".to_string(),
            predecessor_origin: None,
            manifest_hashes: PayloadHashes {
                sha256: [key; 32],
                sha3_256: [key + 1; 32],
            },
            tokens: vec![],
        }
    }

    fn keys_of(groups: &[BindingGroup]) -> Vec<u8> {
        groups
            .iter()
            .map(|group| group.manifest_hashes.sha256[0])
            .collect()
    }

    #[test]
    fn a_binder_precedes_the_stamp_it_binds_regardless_of_payload() {
        let groups = vec![group_with_key(0), group_with_key(9)];
        // The second group binds the first, so it must come first
        // even though its payload is larger
        let ordered = run(
            groups,
            &[BindingEdge {
                binder: 1,
                bound: 0,
            }],
        )
        .expect("an acyclic relation orders");
        assert_eq!(keys_of(&ordered), vec![9, 0]);
    }

    #[test]
    fn unrelated_groups_order_by_payload_bytes() {
        let groups = vec![group_with_key(5), group_with_key(3)];
        let ordered = run(groups, &[]).expect("an empty relation orders");
        assert_eq!(keys_of(&ordered), vec![3, 5]);
    }

    #[test]
    fn a_skip_link_beside_an_unrelated_group_orders_consistently() {
        // The configuration that made the pairwise ordering rule
        // cyclic: A (key 9) binds B (key 0), C (key 5) is unrelated
        // and its payload sits between theirs. The lexicographic
        // minimum of the valid orderings is C, A, B.
        let groups =
            vec![group_with_key(9), group_with_key(0), group_with_key(5)];
        let ordered = run(
            groups,
            &[BindingEdge {
                binder: 0,
                bound: 1,
            }],
        )
        .expect("an acyclic relation orders");
        assert_eq!(keys_of(&ordered), vec![5, 9, 0]);
    }

    #[test]
    fn the_greedy_order_is_the_lexicographic_minimum() {
        let keys = [9u8, 0, 5, 7];
        let edges = [
            BindingEdge {
                binder: 0,
                bound: 1,
            },
            BindingEdge {
                binder: 2,
                bound: 3,
            },
        ];
        let mut smallest_valid: Option<Vec<u8>> = None;
        for first in 0..4usize {
            for second in 0..4usize {
                for third in 0..4usize {
                    for fourth in 0..4usize {
                        let permutation = [first, second, third, fourth];
                        let position = |group: usize| {
                            permutation
                                .iter()
                                .position(|&placed| placed == group)
                                .expect("permutations place every group")
                        };
                        let is_valid = (0..4)
                            .all(|group| permutation.contains(&group))
                            && edges.iter().all(|edge| {
                                position(edge.binder) < position(edge.bound)
                            });
                        let candidate = is_valid.then(|| {
                            permutation
                                .iter()
                                .map(|&group| keys[group])
                                .collect::<Vec<u8>>()
                        });
                        smallest_valid =
                            match (smallest_valid.take(), candidate) {
                                (None, candidate) => candidate,
                                (previous, None) => previous,
                                (Some(previous), Some(current)) => {
                                    Some(previous.min(current))
                                }
                            };
                    }
                }
            }
        }
        let groups = keys.iter().map(|&key| group_with_key(key)).collect();
        let ordered = run(groups, &edges).expect("an acyclic relation orders");
        assert_eq!(
            Some(keys_of(&ordered)),
            smallest_valid,
            "greedy output must equal the brute-forced minimum"
        );
    }

    #[test]
    fn a_cyclic_binding_relation_reports_the_cycle() {
        let groups = vec![group_with_key(0), group_with_key(1)];
        let cyclic_edges = [
            BindingEdge {
                binder: 0,
                bound: 1,
            },
            BindingEdge {
                binder: 1,
                bound: 0,
            },
        ];
        assert_eq!(run(groups, &cyclic_edges), Err(Error::Cycle));
    }

    #[test]
    fn a_self_binding_edge_is_rejected() {
        let groups = vec![group_with_key(0)];
        let self_edge = BindingEdge {
            binder: 0,
            bound: 0,
        };
        assert_eq!(
            run(groups, &[self_edge]),
            Err(Error::InvalidEdge(self_edge))
        );
    }

    #[test]
    fn an_out_of_range_edge_is_rejected() {
        let groups = vec![group_with_key(0)];
        let dangling_edge = BindingEdge {
            binder: 0,
            bound: 7,
        };
        assert_eq!(
            run(groups, &[dangling_edge]),
            Err(Error::InvalidEdge(dangling_edge))
        );
    }
}
