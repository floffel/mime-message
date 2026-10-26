//! Charset decoding for MIME bodies and RFC 2047 encoded-words.
//!
//! Label resolution and decoding are delegated to [`encoding_rs`], the WHATWG
//! encoding registry that browsers ship: every label listed there is understood
//! (`Shift_JIS`, `GBK`, `Big5`, `KOI8-R`, `ISO-8859-2` … `ISO-8859-16`,
//! `windows-125x`, `UTF-16` LE/BE, …), together with the aliases the registry
//! defines for it. A short alias table keeps the non-standard spellings that
//! appear in real mail working (`utf16`, `latin9`), because RFC 2978 asks
//! receivers to be liberal about how a sender spells a label.
//!
//! Only UTF-8 is decoded strictly. Everything else is decoded permissively so
//! that a wrong or unknown `charset` parameter never fails a parse: US-ASCII and
//! ISO-8859-1 are interpreted the way mail clients do (as Windows-1252, so
//! ISO-8859-1 files decode correctly too), malformed byte sequences become
//! U+FFFD, and an unknown or empty label falls back to UTF-8 with replacement
//! characters.
//!
//! A byte-order mark is **not** stripped here: it decodes to U+FEFF and stays
//! part of the text, because `decode(render(value)) == value` is an invariant of
//! this crate - a subject may legitimately start with U+FEFF. Callers that
//! display freshly received mail can trim it themselves.

use encoding_rs::{Encoding, ISO_8859_15, UTF_16BE, UTF_16LE, UTF_8};

/// Spellings that appear in real mail but are not WHATWG labels.
///
/// `Encoding::for_label` is the only resolver for the standard registry; this
/// table exists solely so the labels the crate accepted before it delegated
/// decoding keep their meaning. Nothing else belongs here.
const NON_STANDARD_LABELS: [(&str, &Encoding); 5] = [
    ("utf16", UTF_16LE),
    ("utf16le", UTF_16LE),
    ("utf16be", UTF_16BE),
    ("latin9", ISO_8859_15),
    ("latin-9", ISO_8859_15),
];

/// Decodes `bytes` from `charset` into a `String`.
///
/// The label is matched case-insensitively, tolerates surrounding quotes and
/// whitespace and is resolved through the WHATWG encoding registry, so all
/// registered labels work - not only the Latin ones. Unknown labels never fail:
/// they fall back to UTF-8 with replacement characters.
///
/// ```
/// use mime_message::charset;
///
/// assert_eq!(charset::decode(b"Gr\xc3\xbc\xc3\x9fe", "utf-8"), "Grüße");
/// assert_eq!(charset::decode(b"Gr\xfc\xdfe", "iso-8859-1"), "Grüße");
/// assert_eq!(charset::decode(b"\x80", "windows-1252"), "€");
/// assert_eq!(charset::decode(b"Gr\xfc\xdfe", "iso-8859-15"), "Grüße");
/// // Labels outside the Latin family are decoded with their own tables.
/// assert_eq!(charset::decode(b"\x82\xa0", "shift_jis"), "あ");
/// assert_eq!(charset::decode(b"\xc4\xe3\xba\xc3", "gbk"), "你好");
/// assert_eq!(charset::decode(b"\xf0\xd2\xc9\xd7\xc5\xd4", "koi8-r"), "Привет");
/// // Unknown labels are decoded as UTF-8 rather than rejected.
/// assert_eq!(charset::decode(b"plain", "x-no-such-charset"), "plain");
/// ```
#[must_use]
pub fn decode(bytes: &[u8], charset: &str) -> String {
    // `decode_without_bom_handling` keeps the declared label authoritative and
    // leaves a BOM in the text (see the module note on round-tripping).
    let (text, _had_errors) = resolve(charset).decode_without_bom_handling(bytes);
    text.into_owned()
}

/// Resolves a charset label to its encoding, falling back to UTF-8.
fn resolve(charset: &str) -> &'static Encoding {
    let label = normalise(charset);
    if let Some(encoding) = Encoding::for_label(label.as_bytes()) {
        return encoding;
    }
    NON_STANDARD_LABELS
        .iter()
        .find(|(alias, _)| *alias == label)
        .map_or(UTF_8, |(_, encoding)| encoding)
}

/// Canonicalises a charset label: trims, drops quotes, lowercases.
fn normalise(charset: &str) -> String {
    charset.trim().trim_matches('"').trim().to_ascii_lowercase()
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
        // Undefined Windows-1252 slots stay C1 controls rather than vanishing.
        assert_eq!(decode(&[0x81], "windows-1252"), "\u{0081}");
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
        // Surrogate pairs are joined, not replaced one half at a time.
        let emoji = "🚀";
        let units: Vec<u8> = emoji.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode(&units, "utf-16"), emoji);
    }

    #[test]
    fn labels_outside_the_old_four_families_use_their_own_tables() {
        // Each of these decoded as UTF-8 (mojibake) before the registry was used.
        assert_eq!(decode(b"\x82\xa0", "shift_jis"), "あ");
        assert_eq!(decode(b"\xc4\xe3\xba\xc3", "gbk"), "你好");
        assert_eq!(decode(b"\xa4\x40", "big5"), "一");
        assert_eq!(decode(&[0xB1], "iso-8859-2"), "ą");
        assert_eq!(decode(b"\xf0\xd2\xc9\xd7\xc5\xd4", "koi8-r"), "Привет");
        // Windows-1251, not a Latin table: 0xCF 0xF0 0xE8 is "При".
        assert_eq!(decode(b"\xcf\xf0\xe8", "windows-1251"), "При");
    }

    #[test]
    fn registry_aliases_resolve_to_the_same_encoding() {
        for label in ["sjis", "shift-jis", "x-sjis", "SHIFT_JIS"] {
            assert_eq!(decode(b"\x82\xa0", label), "あ", "label {label}");
        }
        for label in ["latin1", "l1", "cp1252", "ansi_x3.4-1968", "us-ascii"] {
            assert_eq!(decode(&[0x80], label), "€", "label {label}");
        }
    }

    #[test]
    fn non_standard_labels_kept_from_before_are_still_understood() {
        let units: Vec<u8> = "Grüße".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode(&units, "utf16"), "Grüße");
        assert_eq!(decode(&units, "utf16le"), "Grüße");
        assert_eq!(decode(&[0xA4], "latin9"), "€");
        assert_eq!(decode(&[0xA4], "latin-9"), "€");
    }

    #[test]
    fn a_byte_order_mark_stays_part_of_the_text() {
        // Round-trip fidelity: a value may legitimately start with U+FEFF, so the
        // BOM is decoded to a character and only a displaying caller trims it.
        let mut utf8 = vec![0xEF, 0xBB, 0xBF];
        utf8.extend_from_slice("Grüße".as_bytes());
        assert_eq!(decode(&utf8, "utf-8"), "\u{feff}Grüße");
        let mut be = vec![0xFE, 0xFF];
        be.extend("Grüße".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode(&be, "utf-16be"), "\u{feff}Grüße");
        // The same holds for a U+FEFF that is not at the start.
        assert_eq!(decode("a\u{feff}b".as_bytes(), "utf-8"), "a\u{feff}b");
    }

    #[test]
    fn unknown_and_empty_labels_fall_back_to_utf8() {
        assert_eq!(decode(b"Gr\xc3\xbc\xc3\x9fe", "x-broken"), "Grüße");
        assert_eq!(decode(b"abc", ""), "abc");
        assert_eq!(decode(b"abc", "  \"UTF-8\"  "), "abc");
        // A label that is far outside the registry (unicode, punctuation) too.
        assert_eq!(decode(b"abc", "utf-8; charset=utf-8"), "abc");
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
        // WHATWG replacement behaviour: the trailing lone byte is one malformed
        // sequence and becomes U+FFFD rather than being dropped silently.
        assert_eq!(decode(&[0x41], "utf-16"), "\u{FFFD}");
        assert_eq!(decode(&[0x41, 0x00, 0x42], "utf-16le"), "A\u{FFFD}");
        assert_eq!(decode(&[], "utf-16be"), "");
    }

    #[test]
    fn an_unpaired_utf16_surrogate_becomes_one_replacement_character() {
        // 0xD800 is a high surrogate with no low surrogate after it.
        assert_eq!(decode(&[0xD8, 0x00], "utf-16be"), "\u{FFFD}");
        // A high surrogate followed by a normal BMP unit: one replacement, then
        // the unit itself - not two replacements.
        assert_eq!(decode(&[0xD8, 0x00, 0x00, 0x41], "utf-16be"), "\u{FFFD}A");
        // A lone low surrogate is malformed on its own.
        assert_eq!(decode(&[0xDC, 0x00], "utf-16be"), "\u{FFFD}");
    }
}
