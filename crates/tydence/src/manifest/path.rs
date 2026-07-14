use std::cmp::Ordering;

use tydence_ucd::general_category_ranges;

use super::hex;

// Pinned to the Unicode version named by manifest format v1: newer
// tables reclassify code points (Cn above all), and following them
// would let the same tree encode to different canonical manifests
// depending on the implementation (docs/stamping.md §4.3).
static CONTROL_OR_SEPARATOR: &[(u32, u32)] =
    general_category_ranges!("17.0.0", "^[CZ]");

fn is_control_or_separator(code_point: u32) -> bool {
    CONTROL_OR_SEPARATOR
        .binary_search_by(|(first, last)| match code_point {
            probed if probed < *first => Ordering::Greater,
            probed if *last < probed => Ordering::Less,
            _ => Ordering::Equal,
        })
        .is_ok()
}

fn push_escaped(encoded: &mut String, source_bytes: &[u8]) {
    for source_byte in source_bytes {
        encoded.push_str(&format!("%{source_byte:02X}"));
    }
}

fn push_encoded_text(encoded: &mut String, valid_text: &str) {
    for character in valid_text.chars() {
        let keeps_raw =
            character != '%' && !is_control_or_separator(u32::from(character));
        if keeps_raw {
            encoded.push(character);
        } else {
            let mut utf8_buffer = [0u8; 4];
            let character_bytes =
                character.encode_utf8(&mut utf8_buffer).as_bytes();
            push_escaped(encoded, character_bytes);
        }
    }
}

/// Encodes the byte string git stores as a path into the printable
/// form manifest v1 uses for `--path` fields: `%XX` with uppercase
/// hex for `%` itself, for bytes outside valid UTF-8, and for
/// characters in the Unicode general categories C* and Z*;
/// everything visibly rendered stays as-is (`docs/stamping.md`
/// §4.3).
pub fn encode_path(path_bytes: &[u8]) -> String {
    let mut encoded = String::new();
    let mut remaining = path_bytes;
    while !remaining.is_empty() {
        match str::from_utf8(remaining) {
            Ok(valid_text) => {
                push_encoded_text(&mut encoded, valid_text);
                remaining = &[];
            }
            Err(utf8_error) => {
                let (valid_bytes, invalid_start) =
                    remaining.split_at(utf8_error.valid_up_to());
                let valid_text = str::from_utf8(valid_bytes)
                    .expect("valid_up_to bytes are valid UTF-8");
                push_encoded_text(&mut encoded, valid_text);
                // error_len is None only when the buffer ends inside
                // a would-be sequence; everything left is invalid
                let invalid_len =
                    utf8_error.error_len().unwrap_or(invalid_start.len());
                push_escaped(&mut encoded, &invalid_start[..invalid_len]);
                remaining = &invalid_start[invalid_len..];
            }
        }
    }
    encoded
}

/// Decodes a `--path` field back into the byte string git stores:
/// the exact inverse of [`encode_path`] on canonical input. Returns
/// `None` for an empty field or a `%` not followed by two uppercase
/// hex digits; over- or under-escaped spellings decode here and are
/// rejected later by the parser's re-encoding comparison.
pub fn decode_path(encoded_text: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded_text.len());
    let mut encoded_bytes = encoded_text.bytes();
    while let Some(encoded_byte) = encoded_bytes.next() {
        match encoded_byte {
            b'%' => {
                let high =
                    hex::digit_value(hex::UPPERCASE, encoded_bytes.next()?)?;
                let low =
                    hex::digit_value(hex::UPPERCASE, encoded_bytes.next()?)?;
                decoded.push(high * 16 + low);
            }
            _ => decoded.push(encoded_byte),
        }
    }
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_paths_pass_through() {
        assert_eq!(encode_path(b"src/main.rs"), "src/main.rs");
        assert_eq!(encode_path(b"a+b~c!d.txt"), "a+b~c!d.txt");
    }

    #[test]
    fn the_escape_character_itself_is_escaped() {
        assert_eq!(encode_path(b"100%.md"), "100%25.md");
    }

    #[test]
    fn ascii_space_and_controls_are_escaped() {
        assert_eq!(encode_path(b"a b.txt"), "a%20b.txt");
        assert_eq!(encode_path(b"tab\there"), "tab%09here");
        assert_eq!(encode_path(b"line\nfeed"), "line%0Afeed");
        assert_eq!(encode_path(b"\x01"), "%01");
        assert_eq!(encode_path(b"\x7F"), "%7F");
    }

    #[test]
    fn zero_width_and_bidi_characters_are_escaped_per_utf8_byte() {
        assert_eq!(encode_path("a\u{200D}b".as_bytes()), "a%E2%80%8Db");
        assert_eq!(encode_path("x\u{202E}y".as_bytes()), "x%E2%80%AEy");
    }

    #[test]
    fn non_ascii_separators_are_escaped_per_utf8_byte() {
        assert_eq!(encode_path("a\u{3000}b".as_bytes()), "a%E3%80%80b");
        assert_eq!(encode_path("a\u{00A0}b".as_bytes()), "a%C2%A0b");
    }

    #[test]
    fn visible_non_ascii_including_combining_marks_stays_raw() {
        assert_eq!(encode_path("日本語.txt".as_bytes()), "日本語.txt");
        assert_eq!(encode_path("re\u{0301}sume".as_bytes()), "re\u{0301}sume");
    }

    #[test]
    fn bytes_outside_valid_utf8_are_escaped() {
        assert_eq!(encode_path(b"a\xFFb"), "a%FFb");
        assert_eq!(encode_path(b"\xC3"), "%C3");
        // A CESU-style surrogate encoding is not valid UTF-8, so it
        // is escaped byte by byte
        assert_eq!(encode_path(b"a\xED\xA0\x80b"), "a%ED%A0%80b");
    }

    #[test]
    fn overlong_utf8_encodings_are_escaped_not_decoded() {
        // 0xC0 0xAF and 0xE0 0x80 0xAF are overlong spellings of
        // '/'; decoding them would let two distinct byte strings
        // print identically, so they must stay invalid raw bytes
        assert_eq!(encode_path(b"a\xC0\xAFb"), "a%C0%AFb");
        assert_eq!(encode_path(b"a\xE0\x80\xAFb"), "a%E0%80%AFb");
    }

    #[test]
    fn escaping_resumes_cleanly_after_invalid_bytes() {
        assert_eq!(encode_path(b"ok\xFF\xFEok \xC3"), "ok%FF%FEok%20%C3");
    }

    #[test]
    fn unassigned_code_points_are_escaped() {
        // U+0378 is unassigned (Cn) in Unicode 17.0
        assert_eq!(encode_path("a\u{0378}b".as_bytes()), "a%CD%B8b");
    }

    #[test]
    fn decoding_inverts_encoding() {
        let pathological: &[u8] = b"100% \xFF\xC0\xAF\x01ok.txt";
        assert_eq!(
            decode_path(&encode_path(pathological)),
            Some(pathological.to_vec())
        );
        assert_eq!(decode_path("src/main.rs"), Some(b"src/main.rs".to_vec()));
        assert_eq!(decode_path("a%20b"), Some(b"a b".to_vec()));
    }

    #[test]
    fn lowercase_escape_digits_do_not_decode() {
        assert_eq!(decode_path("a%2fb"), None);
        assert_eq!(decode_path("a%fFb"), None);
    }

    #[test]
    fn truncated_escapes_do_not_decode() {
        assert_eq!(decode_path("abc%"), None);
        assert_eq!(decode_path("abc%2"), None);
    }

    #[test]
    fn non_hex_escape_digits_do_not_decode() {
        assert_eq!(decode_path("a%G0b"), None);
        assert_eq!(decode_path("a%%25b"), None);
    }

    #[test]
    fn an_empty_field_does_not_decode() {
        assert_eq!(decode_path(""), None);
    }
}
