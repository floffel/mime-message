//! RFC 2047 encoded-word decoding (`=?charset?B?…?=` / `=?charset?Q?…?=`).
//!
//! Encoding lives in the renderer; this module is the inverse. It accepts the
//! sloppiness found in real mail: lower-case encodings, junk between adjacent
//! words, unknown charsets, and payloads that are not valid base64. A word that
//! cannot be decoded is left in the output verbatim rather than dropped, so no
//! input text disappears.
//!
//! [`decode`] itself does not police the result — it is a pure transformation.
//! [`Message::parse`](crate::Message::parse) rejects decoded header values that
//! contain line breaks, so a word such as `=?utf-8?B?aGkNCkJjYzogZXZpbA==?=`
//! cannot smuggle a `Bcc:` header.

use crate::charset;
use crate::transfer;

/// Longest charset label accepted inside an encoded-word.
const MAX_CHARSET_LEN: usize = 100;

/// Decodes every RFC 2047 encoded-word in `input`.
///
/// Whitespace between two adjacent encoded-words is removed, as RFC 2047 §6.2
/// requires, while other text (including single spaces between a word and plain
/// text) is preserved.
///
/// ```
/// use mime_message::rfc2047;
///
/// assert_eq!(rfc2047::decode("=?UTF-8?B?R3LDvMOfZQ==?="), "Grüße");
/// assert_eq!(rfc2047::decode("=?iso-8859-1?Q?Gr=FC=DFe?="), "Grüße");
/// // Adjacent words lose the separating whitespace.
/// assert_eq!(rfc2047::decode("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
/// // Ordinary text is untouched.
/// assert_eq!(rfc2047::decode("plain subject"), "plain subject");
/// ```
#[must_use]
pub fn decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    let mut previous_was_word = false;

    while index < input.len() {
        if is_word_start(input, index) {
            if let Some((decoded, end)) = decode_word(input, index) {
                out.push_str(&decoded);
                index = end;
                previous_was_word = true;
                continue;
            }
        }

        let rest = &input[index..];
        let Some(ch) = rest.chars().next() else { break };

        if ch.is_ascii_whitespace() {
            let gap_len = rest
                .char_indices()
                .find(|(_, c)| !c.is_ascii_whitespace())
                .map_or(rest.len(), |(offset, _)| offset);
            let after_gap = index + gap_len;
            // RFC 2047 §6.2: whitespace between adjacent encoded-words is
            // not part of the text.
            if previous_was_word && is_word_start(input, after_gap) {
                index = after_gap;
                continue;
            }
            out.push_str(&rest[..gap_len]);
            index = after_gap;
            previous_was_word = false;
            continue;
        }

        out.push(ch);
        index += ch.len_utf8();
        previous_was_word = false;
    }

    out
}

fn is_word_start(input: &str, index: usize) -> bool {
    input.as_bytes().get(index) == Some(&b'=') && input.as_bytes().get(index + 1) == Some(&b'?')
}

/// Decodes one encoded-word starting at `start`.
///
/// Returns `None` when the text only looks like an encoded-word (missing
/// terminator, unknown encoding, undecodable payload); the caller then copies it
/// verbatim.
fn decode_word(input: &str, start: usize) -> Option<(String, usize)> {
    let body_start = start + 2;
    let charset_end = body_start + input[body_start..].find('?')?;
    let charset = &input[body_start..charset_end];

    if charset.is_empty()
        || charset.len() > MAX_CHARSET_LEN
        || !charset.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }

    let encoding = *input.as_bytes().get(charset_end + 1)?;
    if input.as_bytes().get(charset_end + 2) != Some(&b'?') {
        return None;
    }

    let payload_start = charset_end + 3;
    let payload_end = payload_start + input[payload_start..].find("?=")?;
    let payload = &input[payload_start..payload_end];

    let bytes = match encoding {
        b'B' | b'b' => transfer::decode_base64(payload).ok()?,
        b'Q' | b'q' => decode_q(payload),
        _ => return None,
    };

    Some((charset::decode(&bytes, charset), payload_end + 2))
}

/// RFC 2047 "Q" encoding: `_` is a space, `=XX` is a byte.
///
/// Invalid escapes are kept literally, matching [`transfer`]'s permissiveness.
fn decode_q(payload: &str) -> Vec<u8> {
    let bytes = payload.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {
                let decoded = bytes.get(i + 1).copied().zip(bytes.get(i + 2).copied());
                if let Some(value) = decoded.and_then(|(high, low)| hex_pair(high, low)) {
                    out.push(value);
                    i += 3;
                } else {
                    out.push(b'=');
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? * 16 + hex_digit(low)?)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_q_words() {
        assert_eq!(decode("=?UTF-8?B?R3LDvMOfZQ==?="), "Grüße");
        assert_eq!(decode("=?UTF-8?Q?Gr=C3=BC=C3=9Fe?="), "Grüße");
        assert_eq!(decode("=?UTF-8?Q?a_b?="), "a b");
        assert_eq!(decode("=?utf-8?b?YWJj?="), "abc");
    }

    #[test]
    fn adjacent_words_join_without_the_gap() {
        assert_eq!(decode("=?UTF-8?Q?a?= =?UTF-8?Q?b?="), "ab");
        assert_eq!(decode("=?UTF-8?Q?a?=\t\r\n =?UTF-8?Q?b?="), "ab");
        // A word followed by plain text keeps the separating space.
        assert_eq!(decode("=?UTF-8?Q?a?= b"), "a b");
        assert_eq!(decode("x =?UTF-8?Q?a?="), "x a");
    }

    #[test]
    fn mixed_charsets_decode_per_word() {
        assert_eq!(
            decode("=?iso-8859-1?Q?Gr=FC=DFe?= =?UTF-8?Q?=E2=82=AC?="),
            "Grüße€"
        );
    }

    #[test]
    fn broken_words_are_preserved_verbatim() {
        assert_eq!(decode("=?UTF-8?B?%%%?="), "=?UTF-8?B?%%%?=");
        assert_eq!(decode("=?UTF-8?X?abc?="), "=?UTF-8?X?abc?=");
        assert_eq!(decode("=?UTF-8?B?abc"), "=?UTF-8?B?abc");
        assert_eq!(decode("=?nope?B?YWJj?="), "abc");
        assert_eq!(decode("=?"), "=?");
        assert_eq!(decode(""), "");
    }

    #[test]
    fn unknown_charset_falls_back_to_utf8() {
        assert_eq!(decode("=?x-unknown?B?R3LDvMOfZQ==?="), "Grüße");
    }

    #[test]
    fn q_encoding_keeps_malformed_escapes() {
        assert_eq!(decode("=?UTF-8?Q?a=ZZb?="), "a=ZZb");
    }

    #[test]
    fn newlines_survive_decoding_and_are_rejected_by_the_parser() {
        // The decoder is a pure transformation; smuggling is stopped in parse().
        let smuggled = decode("=?UTF-8?B?aGkNCkJjYzogZXZpbA==?=");
        assert_eq!(smuggled, "hi\r\nBcc: evil");
    }

    #[test]
    fn long_charset_label_is_not_an_encoded_word() {
        let label = "x".repeat(200);
        let input = format!("=?{label}?B?YWJj?=");
        assert_eq!(decode(&input), input);
    }
}
