/// A canonical hex alphabet: the sixteen digit spellings in value
/// order. Each context admits exactly one alphabet — lowercase for
/// payload hashes, uppercase for path escapes — so the table that
/// spells a value is also the whole set of spellings that parse,
/// and neither case can drift into accepting the other.
pub const LOWERCASE: &[u8; 16] = b"0123456789abcdef";
pub const UPPERCASE: &[u8; 16] = b"0123456789ABCDEF";

pub fn digit_value(alphabet: &[u8; 16], hex_byte: u8) -> Option<u8> {
    alphabet
        .iter()
        .position(|spelling| *spelling == hex_byte)
        .map(|digit| digit as u8)
}

pub fn encode(alphabet: &[u8; 16], payload_bytes: &[u8]) -> String {
    payload_bytes
        .iter()
        .flat_map(|payload_byte| {
            [
                char::from(alphabet[usize::from(payload_byte >> 4)]),
                char::from(alphabet[usize::from(payload_byte & 0x0F)]),
            ]
        })
        .collect()
}

/// Decodes exactly `BYTE_COUNT` bytes spelled in the given
/// alphabet; any other length or spelling is `None`.
pub fn decode<const BYTE_COUNT: usize>(
    alphabet: &[u8; 16],
    hex_text: &str,
) -> Option<[u8; BYTE_COUNT]> {
    let hex_bytes = hex_text.as_bytes();
    if hex_bytes.len() != BYTE_COUNT * 2 {
        return None;
    }
    let mut decoded = [0u8; BYTE_COUNT];
    for (decoded_slot, digit_pair) in
        decoded.iter_mut().zip(hex_bytes.chunks_exact(2))
    {
        let high = digit_value(alphabet, digit_pair[0])?;
        let low = digit_value(alphabet, digit_pair[1])?;
        *decoded_slot = high * 16 + low;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_alphabet_admits_exactly_its_own_spellings() {
        assert_eq!(digit_value(LOWERCASE, b'0'), Some(0));
        assert_eq!(digit_value(LOWERCASE, b'a'), Some(10));
        assert_eq!(digit_value(LOWERCASE, b'f'), Some(15));
        assert_eq!(digit_value(LOWERCASE, b'A'), None);
        assert_eq!(digit_value(LOWERCASE, b'g'), None);
        assert_eq!(digit_value(UPPERCASE, b'7'), Some(7));
        assert_eq!(digit_value(UPPERCASE, b'A'), Some(10));
        assert_eq!(digit_value(UPPERCASE, b'F'), Some(15));
        assert_eq!(digit_value(UPPERCASE, b'a'), None);
    }

    #[test]
    fn encoding_and_decoding_invert_through_one_alphabet() {
        assert_eq!(encode(LOWERCASE, &[0x0F, 0xA0]), "0fa0");
        assert_eq!(encode(UPPERCASE, &[0x0F, 0xA0]), "0FA0");
        assert_eq!(decode(LOWERCASE, "0fa0"), Some([0x0F, 0xA0]));
        assert_eq!(decode(UPPERCASE, "0FA0"), Some([0x0F, 0xA0]));
        assert_eq!(decode::<2>(LOWERCASE, "0FA0"), None);
    }

    #[test]
    fn decoding_rejects_any_other_length() {
        assert_eq!(decode::<2>(LOWERCASE, "0fa"), None);
        assert_eq!(decode::<2>(LOWERCASE, "0fa0a1"), None);
        assert_eq!(decode::<2>(LOWERCASE, ""), None);
    }
}
