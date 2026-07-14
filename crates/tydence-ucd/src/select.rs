use regex::Regex;

use super::parse::CategorizedRange;

// A proven regex engine over a bespoke matcher: today's callers
// only need prefix and exact matches, but the selection instrument
// must not be the weak link, and the dependency stays host-side
// with the proc-macro, never in the target binary.
fn compile(pattern_text: &str) -> Regex {
    Regex::new(pattern_text).unwrap_or_else(|regex_error| {
        panic!("invalid category pattern {pattern_text:?}: {regex_error}")
    })
}

pub fn run(
    categorized_ranges: &[CategorizedRange],
    pattern_text: &str,
) -> Vec<(u32, u32)> {
    let category_regex = compile(pattern_text);
    let selected_ranges = categorized_ranges
        .iter()
        .filter(|range| category_regex.is_match(range.category));
    let mut merged_ranges: Vec<(u32, u32)> = Vec::new();
    for range in selected_ranges {
        match merged_ranges.last_mut() {
            Some((_, merged_last)) if *merged_last + 1 == range.first => {
                *merged_last = range.last;
            }
            _ => merged_ranges.push((range.first, range.last)),
        }
    }
    assert!(
        !merged_ranges.is_empty(),
        "category pattern {pattern_text:?} selects no category"
    );
    merged_ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RANGES: &[CategorizedRange<'static>] = &[
        CategorizedRange {
            first: 0x0000,
            last: 0x001F,
            category: "Cc",
        },
        CategorizedRange {
            first: 0x0020,
            last: 0x0020,
            category: "Zs",
        },
        CategorizedRange {
            first: 0x0021,
            last: 0x00FF,
            category: "Po",
        },
        CategorizedRange {
            first: 0x0100,
            last: 0x10FFFF,
            category: "Lo",
        },
    ];

    #[test]
    fn an_anchored_class_selects_by_first_letter_and_merges_neighbors() {
        assert_eq!(run(TEST_RANGES, "^[CZ]"), vec![(0x0000, 0x0020)]);
    }

    #[test]
    fn an_exact_name_pattern_selects_a_single_category() {
        assert_eq!(run(TEST_RANGES, "^Zs$"), vec![(0x0020, 0x0020)]);
    }

    #[test]
    fn an_alternation_selects_the_named_categories() {
        assert_eq!(run(TEST_RANGES, "^(Cc|Zs)$"), vec![(0x0000, 0x0020)]);
    }

    #[test]
    fn an_unanchored_pattern_searches_anywhere_in_the_name() {
        assert_eq!(run(TEST_RANGES, "o"), vec![(0x0021, 0x10FFFF)]);
    }

    #[test]
    fn non_adjacent_selections_stay_separate() {
        assert_eq!(
            run(TEST_RANGES, "^[CL]"),
            vec![(0x0000, 0x001F), (0x0100, 0x10FFFF)]
        );
    }

    #[test]
    #[should_panic(expected = "selects no category")]
    fn rejects_a_pattern_matching_nothing() {
        run(TEST_RANGES, "^X");
    }

    #[test]
    #[should_panic(expected = "invalid category pattern")]
    fn rejects_a_malformed_regex() {
        run(TEST_RANGES, "[CZ");
    }
}
