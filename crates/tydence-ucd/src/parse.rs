// Everything here panics on surprise instead of skipping: this
// feeds the character tables a manifest format version is pinned
// to, so a line the parser does not understand must fail the build.

#[derive(Debug, PartialEq, Eq)]
pub struct CategorizedRange<'source> {
    pub first: u32,
    pub last: u32,
    pub category: &'source str,
}

fn parse_code_point(hex_field: &str) -> u32 {
    u32::from_str_radix(hex_field, 16).unwrap_or_else(|parse_error| {
        panic!("invalid code point {hex_field:?}: {parse_error}")
    })
}

fn parse_code_point_range(range_field: &str) -> (u32, u32) {
    match range_field.split_once("..") {
        Some((first_field, last_field)) => {
            (parse_code_point(first_field), parse_code_point(last_field))
        }
        None => {
            let code_point = parse_code_point(range_field);
            (code_point, code_point)
        }
    }
}

fn parse_category(category_field: &str) -> &str {
    let category_bytes = category_field.as_bytes();
    let is_well_formed = category_bytes.len() == 2
        && category_bytes[0].is_ascii_uppercase()
        && category_bytes[1].is_ascii_lowercase();
    assert!(
        is_well_formed,
        "malformed general category {category_field:?}"
    );
    category_field
}

fn parse_data_line(data_line: &str) -> CategorizedRange<'_> {
    let Some((range_field, category_field)) = data_line.split_once(';') else {
        panic!("malformed UCD line {data_line:?}");
    };
    let (first, last) = parse_code_point_range(range_field.trim());
    CategorizedRange {
        first,
        last,
        category: parse_category(category_field.trim()),
    }
}

// The extracted UCD file assigns every code point exactly one
// category, so the parsed ranges must tile 0..=0x10FFFF with no gap
// or overlap. Verifying that proves no line was lost to a parsing
// or comment-stripping mistake.
fn verify_partition(sorted_ranges: &[CategorizedRange]) {
    let mut expected_first = 0u32;
    for range in sorted_ranges {
        assert!(
            range.first == expected_first && range.first <= range.last,
            "UCD ranges do not tile the code space at U+{:04X}",
            range.first
        );
        expected_first = range.last + 1;
    }
    assert!(
        expected_first == 0x110000,
        "UCD ranges stop short of U+10FFFF"
    );
}

pub fn run(ucd_source: &str) -> Vec<CategorizedRange<'_>> {
    let mut categorized_ranges = Vec::new();
    for source_line in ucd_source.lines() {
        let data_part = match source_line.split_once('#') {
            Some((before_comment, _)) => before_comment.trim(),
            None => source_line.trim(),
        };
        if data_part.is_empty() {
            continue;
        }
        categorized_ranges.push(parse_data_line(data_part));
    }
    // The source file groups lines by category, so code point order
    // has to be restored before the tiling check and the emission
    categorized_ranges.sort_unstable_by_key(|range| range.first);
    verify_partition(&categorized_ranges);
    categorized_ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal source that still tiles the whole code space, so
    // the partition check accepts it.
    const TILED_SOURCE: &str = "\
# comment line
0000..001F    ; Cc # controls
0020          ; Zs # space

0021..00FF    ; Po # visible filler
0100..10FFFF  ; Lo # visible filler
";

    #[test]
    fn parses_data_lines_and_skips_comments_and_blanks() {
        assert_eq!(
            run(TILED_SOURCE),
            vec![
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
            ]
        );
    }

    #[test]
    fn orders_ranges_by_code_point_not_by_source_order() {
        let category_grouped_source = "\
0100..10FFFF  ; Lo # listed before lower code points
0000..001F    ; Cc
0020..00FF    ; Zs
";
        assert_eq!(
            run(category_grouped_source),
            vec![
                CategorizedRange {
                    first: 0x0000,
                    last: 0x001F,
                    category: "Cc",
                },
                CategorizedRange {
                    first: 0x0020,
                    last: 0x00FF,
                    category: "Zs",
                },
                CategorizedRange {
                    first: 0x0100,
                    last: 0x10FFFF,
                    category: "Lo",
                },
            ]
        );
    }

    #[test]
    #[should_panic(expected = "malformed UCD line")]
    fn rejects_a_line_without_a_category_field() {
        run("0000..10FFFF\n");
    }

    #[test]
    #[should_panic(expected = "malformed general category")]
    fn rejects_a_malformed_category_name() {
        run("0000..10FFFF  ; Control\n");
    }

    #[test]
    #[should_panic(expected = "invalid code point")]
    fn rejects_a_non_hexadecimal_code_point() {
        run("XYZ..10FFFF   ; Cc\n");
    }

    #[test]
    #[should_panic(expected = "do not tile the code space")]
    fn rejects_a_gap_in_the_code_space() {
        run("0000..001F    ; Cc\n0021..10FFFF  ; Lo\n");
    }

    #[test]
    #[should_panic(expected = "do not tile the code space")]
    fn rejects_overlapping_ranges() {
        run("0000..0020    ; Cc\n0020..10FFFF  ; Lo\n");
    }

    #[test]
    #[should_panic(expected = "stop short of U+10FFFF")]
    fn rejects_a_source_missing_the_top_of_the_code_space() {
        run("0000..FFFF    ; Cc\n");
    }
}
