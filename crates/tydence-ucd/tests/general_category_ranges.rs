use std::cmp::Ordering;

use tydence_ucd::general_category_ranges;

static CONTROL_OR_SEPARATOR: &[(u32, u32)] =
    general_category_ranges!("17.0.0", "^[CZ]");

static SPACE_SEPARATOR: &[(u32, u32)] =
    general_category_ranges!("17.0.0", "^Zs$");

static SEPARATOR_BY_ESCAPE: &[(u32, u32)] =
    general_category_ranges!("17.0.0", "^Z\\w");

fn contains(ranges: &[(u32, u32)], code_point: u32) -> bool {
    ranges
        .binary_search_by(|(first, last)| match code_point {
            probed if probed < *first => Ordering::Greater,
            probed if *last < probed => Ordering::Less,
            _ => Ordering::Equal,
        })
        .is_ok()
}

#[test]
fn tables_are_sorted_merged_and_well_formed() {
    for ranges in [CONTROL_OR_SEPARATOR, SPACE_SEPARATOR] {
        assert!(!ranges.is_empty());
        for (first, last) in ranges {
            assert!(first <= last);
        }
        for window in ranges.windows(2) {
            let (_, previous_last) = window[0];
            let (next_first, _) = window[1];
            // Strict separation proves adjacent ranges were merged
            assert!(previous_last + 1 < next_first);
        }
    }
}

#[test]
fn selection_merges_adjacent_ranges_across_categories() {
    // U+007F..U+009F are Cc and U+00A0 is Zs: distinct categories,
    // numerically adjacent, so a C*/Z* selection must fuse them
    let containing_delete = CONTROL_OR_SEPARATOR
        .iter()
        .find(|(first, last)| (*first..=*last).contains(&0x007F))
        .expect("U+007F is a control character");
    assert!(containing_delete.1 >= 0x00A0);
}

#[test]
fn escape_sequences_in_the_pattern_reach_the_regex_decoded() {
    // Source spells "^Z\\w"; the regex must receive the two-byte
    // sequence \w, not a literal backslash pair, so Z* separators
    // are selected. With undecoded token text this table would be
    // empty and the build would fail.
    assert!(contains(SEPARATOR_BY_ESCAPE, 0x2028));
    assert!(contains(SEPARATOR_BY_ESCAPE, 0x3000));
    assert!(!contains(SEPARATOR_BY_ESCAPE, 0x0000));
}

#[test]
fn an_exact_name_pattern_selects_only_that_category() {
    // IDEOGRAPHIC SPACE is Zs; LINE SEPARATOR (Zl), NUL (Cc) and
    // letters are outside the Zs selection
    assert!(contains(SPACE_SEPARATOR, 0x3000));
    assert!(contains(SPACE_SEPARATOR, 0x0020));
    assert!(!contains(SPACE_SEPARATOR, 0x2028));
    assert!(!contains(SPACE_SEPARATOR, 0x0000));
    assert!(!contains(SPACE_SEPARATOR, u32::from('A')));
}

#[test]
fn ascii_controls_and_space_are_controls_or_separators() {
    assert!(contains(CONTROL_OR_SEPARATOR, 0x0000));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x001F));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x0020));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x007F));
}

#[test]
fn visible_ascii_is_not_a_control_or_separator() {
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('A')));
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('0')));
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('+')));
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('~')));
}

#[test]
fn zero_width_and_joining_characters_are_controls_or_separators() {
    // ZWSP, ZWNJ, ZWJ
    assert!(contains(CONTROL_OR_SEPARATOR, 0x200B));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x200C));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x200D));
}

#[test]
fn bidirectional_controls_are_controls_or_separators() {
    // RIGHT-TO-LEFT OVERRIDE, LEFT-TO-RIGHT ISOLATE
    assert!(contains(CONTROL_OR_SEPARATOR, 0x202E));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x2066));
}

#[test]
fn non_ascii_separators_are_controls_or_separators() {
    // NO-BREAK SPACE, LINE SEPARATOR, PARAGRAPH SEPARATOR,
    // IDEOGRAPHIC SPACE
    assert!(contains(CONTROL_OR_SEPARATOR, 0x00A0));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x2028));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x2029));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x3000));
}

#[test]
fn visible_non_ascii_including_combining_marks_is_not_selected() {
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('あ')));
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('é')));
    assert!(!contains(CONTROL_OR_SEPARATOR, u32::from('中')));
    // COMBINING ACUTE ACCENT: rendered (Mn), so the format keeps it
    assert!(!contains(CONTROL_OR_SEPARATOR, 0x0301));
}

#[test]
fn surrogate_private_use_and_unassigned_are_controls_or_separators() {
    assert!(contains(CONTROL_OR_SEPARATOR, 0xD800));
    assert!(contains(CONTROL_OR_SEPARATOR, 0xE000));
    // Unassigned in Unicode 17.0, and a plane-16 noncharacter
    assert!(contains(CONTROL_OR_SEPARATOR, 0x0378));
    assert!(contains(CONTROL_OR_SEPARATOR, 0x10FFFE));
}
