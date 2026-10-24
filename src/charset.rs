//! Charset decoding for MIME bodies and RFC 2047 encoded-words.
//!
//! Only UTF-8 is decoded strictly. Everything else is decoded permissively so
//! that a wrong or unknown `charset` parameter never fails a parse: ISO-8859-1
//! and US-ASCII are interpreted the way mail clients do (as Windows-1252 for
//! the `0x80..=0x9F` range), ISO-8859-15 gets its eight substitutions, UTF-16
//! is decoded through `char::decode_utf16`, and unknown labels fall back to
//! UTF-8 with replacement characters.

/// Windows-1252 replacements for `0x80..=0x9F` (undefined slots stay C1).
const CP1252: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// ISO-8859-15 differences from ISO-8859-1.
const LATIN9: [(u8, char); 8] = [
    (0xA4, '\u{20AC}'),
    (0xA6, '\u{0160}'),
    (0xA8, '\u{0161}'),
    (0xB4, '\u{017D}'),
    (0xB8, '\u{017E}'),
    (0xBC, '\u{0152}'),
    (0xBD, '\u{0153}'),
    (0xBE, '\u{0178}'),
];

/// Decodes `bytes` from `charset` into a `String`.
///
/// The label is matched case-insensitively and tolerates surrounding quotes and
/// whitespace. Unknown labels never fail: they fall back to UTF-8 with
/// replacement characters.
///
/// ```
/// use mime_message::charset;
///
/// assert_eq!(charset::decode(b"Gr\xc3\xbc\xc3\x9fe", "utf-8"), "Grüße");
/// assert_eq!(charset::decode(b"Gr\xfc\xdfe", "iso-8859-1"), "Grüße");
/// assert_eq!(charset::decode(b"\x80", "windows-1252"), "€");
/// assert_eq!(charset::decode(b"Gr\xfc\xdfe", "iso-8859-15"), "Grüße");
/// // Unknown labels are decoded as UTF-8 rather than rejected.
/// assert_eq!(charset::decode(b"plain", "x-no-such-charset"), "plain");
/// ```
#[must_use]
pub fn decode(bytes: &[u8], charset: &str) -> String {
    let label = normalise(charset);
    let decoder: fn(&[u8]) -> String = match label.as_str() {
        "us-ascii" | "ascii" | "ansi_x3.4-1968" | "iso-ir-6" | "iso-8859-1" | "iso8859-1"
        | "latin1" | "latin-1" | "l1" | "cp1252" | "windows-1252" | "x-cp1252" => decode_cp1252,
        "iso-8859-15" | "iso8859-15" | "latin9" | "latin-9" | "l9" => decode_latin9,
        "utf-16" | "utf-16le" | "utf16" => decode_utf16_le,
        "utf-16be" => decode_utf16_be,
        // UTF-8, and the permissive fallback for unknown labels.
        _ => decode_utf8,
    };
    decoder(bytes)
}

fn decode_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Canonicalises a charset label: trims, drops quotes, lowercases.
fn normalise(charset: &str) -> String {
    charset.trim().trim_matches('"').trim().to_ascii_lowercase()
}

fn decode_cp1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x80..=0x9F).contains(&b) {
                CP1252[usize::from(b - 0x80)]
            } else {
                char::from(b)
            }
        })
        .collect()
}

fn decode_latin9(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            LATIN9
                .iter()
                .find(|(byte, _)| *byte == b)
                .map_or_else(|| char::from(b), |(_, replacement)| *replacement)
        })
        .collect()
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    decode_utf16(bytes, true)
}

fn decode_utf16_be(bytes: &[u8]) -> String {
    decode_utf16(bytes, false)
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units = bytes.as_chunks::<2>().0.iter().map(|pair| {
        if little_endian {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        }
    });
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_keeps_multibyte_text() {
        assert_eq!(decode("Grüße".as_bytes(), "UTF-8"), "Grüße");
    }

    #[test]
    fn latin1_and_cp1252_agree_on_the_c1_range() {
        // Clients treat ISO-8859-1 bytes in 0x80..=0x9F as Windows-1252.
        assert_eq!(decode(&[0x80], "iso-8859-1"), "€");
        assert_eq!(decode(&[0x93], "latin1"), "\u{201C}");
    }

    #[test]
    fn latin9_has_the_euro_sign_and_oe() {
        assert_eq!(decode(&[0xA4], "iso-8859-15"), "€");
        assert_eq!(decode(&[0xBC], "iso8859-15"), "Œ");
        // 0xA4 in plain latin-1 is a currency sign, not the euro.
        assert_eq!(decode(&[0xA4], "iso-8859-1"), "¤");
    }

    #[test]
    fn utf16_both_byte_orders() {
        let text = "Grüße";
        let mut le = Vec::new();
        let mut be = Vec::new();
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
            be.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(decode(&le, "utf-16le"), text);
        assert_eq!(decode(&be, "utf-16be"), text);
    }

    #[test]
    fn unknown_and_empty_labels_fall_back_to_utf8() {
        assert_eq!(decode(b"Gr\xc3\xbc\xc3\x9fe", "x-broken"), "Grüße");
        assert_eq!(decode(b"abc", ""), "abc");
        assert_eq!(decode(b"abc", "  \"UTF-8\"  "), "abc");
    }

    #[test]
    fn invalid_utf8_is_replaced_not_rejected() {
        let decoded = decode(b"a\xffb", "utf-8");
        assert!(decoded.starts_with('a'));
        assert!(decoded.ends_with('b'));
        assert!(decoded.contains(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn odd_utf16_length_does_not_panic() {
        assert_eq!(decode(&[0x41], "utf-16"), "");
        assert_eq!(decode(&[], "utf-16be"), "");
    }
}
