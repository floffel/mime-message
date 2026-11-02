//! `Content-Transfer-Encoding` decoding: base64 and quoted-printable.
//!
//! Both decoders are deliberately lenient about the things real mail servers
//! get wrong (line wrapping, missing padding, stray whitespace) and strict about
//! the things that hide data (characters outside the alphabet). Neither can
//! panic, and both bound their output by the input length.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;

use crate::error::{Error, Result};

/// Base64 that accepts missing padding and non-zero trailing bits.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Decodes a base64 body or encoded-word payload.
///
/// ASCII whitespace is ignored (MIME wraps base64 at 76 columns) and padding is
/// optional. Any other character outside the alphabet is an
/// [`Error::InvalidBase64`].
///
/// ```
/// use mime_message::transfer;
///
/// assert_eq!(transfer::decode_base64("SGVsbG8=").unwrap(), b"Hello");
/// // Wrapped and unpadded input decodes identically.
/// assert_eq!(transfer::decode_base64("SGVs\r\nbG8").unwrap(), b"Hello");
/// assert!(transfer::decode_base64("SGVsbG8*").is_err());
/// ```
///
/// # Errors
///
/// Returns [`Error::InvalidBase64`] when the payload contains characters outside
/// the base64 alphabet or impossible padding. The error carries the byte offset
/// in `input` — line breaks and spaces counted — of the byte the decoder
/// rejected, or `input.len()` when only the length or the padding is wrong, and
/// `part: 0`, because a payload decoded on its own is not part of a message.
pub fn decode_base64(input: &str) -> Result<Vec<u8>> {
    decode_base64_in_part(input, 0)
}

/// [`decode_base64`] for the body of entity number `part` of a parsed message.
pub(crate) fn decode_base64_in_part(input: &str, part: usize) -> Result<Vec<u8>> {
    let mut compact = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        if !byte.is_ascii_whitespace() {
            compact.push(byte);
        }
    }
    LENIENT
        .decode(&compact)
        .map_err(|error| Error::InvalidBase64 {
            part,
            offset: rejected_offset(input, &error),
        })
}

/// Maps the decoder's verdict onto a byte offset in `input`.
///
/// The decoder counts in the whitespace-free payload it was handed, which is not
/// the offset a caller can look up in the message; the offset is therefore mapped
/// back onto the input as it arrived.
fn rejected_offset(input: &str, error: &base64::DecodeError) -> usize {
    let index = match *error {
        base64::DecodeError::InvalidByte(index, _)
        | base64::DecodeError::InvalidLastSymbol { offset: index, .. } => index,
        // No byte is wrong, only how many there are: the payload stops short or
        // its padding is impossible, so the error sits just past its end.
        base64::DecodeError::InvalidLength(_) | base64::DecodeError::InvalidPadding => {
            return input.len();
        }
    };
    nth_payload_byte(input, index).unwrap_or(input.len())
}

/// The input offset of the `n`-th byte that survives the whitespace filter.
fn nth_payload_byte(input: &str, n: usize) -> Option<usize> {
    input
        .bytes()
        .enumerate()
        .filter(|(_, byte)| !byte.is_ascii_whitespace())
        .nth(n)
        .map(|(offset, _)| offset)
}

/// Decodes a quoted-printable body.
///
/// Soft line breaks (`=` at the end of a line) are removed, `=XX` becomes the
/// byte `0xXX`, and everything else is copied verbatim. Malformed escapes are
/// kept as literal text instead of failing the parse — quoted-printable damage
/// is common and never a security boundary.
///
/// ```
/// use mime_message::transfer;
///
/// assert_eq!(transfer::decode_quoted_printable("Gr=C3=BC=C3=9Fe"), "Grüße".as_bytes());
/// assert_eq!(transfer::decode_quoted_printable("a=\r\nb"), b"ab");
/// assert_eq!(transfer::decode_quoted_printable("100% =3D 100%"), b"100% = 100%");
/// ```
#[must_use]
pub fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'=' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            // Trailing '=' means the message was truncated: drop it.
            None => break,
            Some(b'\r') => {
                i += if bytes.get(i + 2) == Some(&b'\n') {
                    3
                } else {
                    2
                };
            }
            Some(b'\n') => i += 2,
            Some(high) => {
                if let Some(value) = hex_pair(*high, bytes.get(i + 2)) {
                    out.push(value);
                    i += 3;
                } else {
                    // Not a valid escape: keep the '=' literally.
                    out.push(b'=');
                    i += 1;
                }
            }
        }
    }
    out
}

/// Upper-case hex digits for `=XX` escapes.
const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// Longest line the encoder emits, in characters, a soft line break included
/// (RFC 2045 §6.7 allows at most 76).
pub const MAX_QUOTED_PRINTABLE_LINE: usize = 76;

/// Encodes `input` as quoted-printable, the 7-bit-safe form of a body.
///
/// The inverse of [`decode_quoted_printable`], with the rules from RFC 2045
/// §6.7: printable US-ASCII except `=` passes through unchanged, everything
/// else becomes `=XX`, a space or tab that ends a line is escaped (a trailing
/// space would be stripped by the next hop), and long lines are broken with a
/// soft line break (`=` + CRLF) so that no line exceeds 76 characters. A line
/// break in the input is a *hard* break and stays one; it is emitted as CRLF, so
/// pass CRLF-normalised text when the output must match the input byte for byte.
///
/// ```
/// use mime_message::transfer;
///
/// // Bytes outside US-ASCII become escapes, not raw 8-bit.
/// assert_eq!(transfer::encode_quoted_printable("Grüße"), "Gr=C3=BC=C3=9Fe");
/// assert_eq!(transfer::encode_quoted_printable("a=b"), "a=3Db");
/// // A trailing space would be lost in transit, so it is escaped.
/// assert_eq!(transfer::encode_quoted_printable("hallo \r\n"), "hallo=20\r\n");
/// // Soft line breaks keep every line within 76 characters, and an encoded body
/// // decodes back to exactly what went in.
/// let input = "ä".repeat(100);
/// let encoded = transfer::encode_quoted_printable(&input);
/// assert!(encoded.split("\r\n").all(|line| line.len() <= 76));
/// assert_eq!(transfer::decode_quoted_printable(&encoded), input.as_bytes());
/// assert_eq!(transfer::encode_quoted_printable(""), "");
/// ```
#[must_use]
pub fn encode_quoted_printable(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 3 + 8);
    let mut column = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];

        // A line break in the input is a hard break and stays one.
        if byte == b'\r' || byte == b'\n' {
            let width = if byte == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
            index += width;
            out.push_str("\r\n");
            column = 0;
            continue;
        }

        // A space or tab that ends the line is invisible in transit, so it is
        // only ever emitted as an escape.
        let trailing = matches!(byte, b' ' | b'\t')
            && matches!(bytes.get(index + 1), None | Some(b'\r' | b'\n'));
        let literal = !trailing
            && (matches!(byte, b' ' | b'\t') || (33..=126).contains(&byte))
            && byte != b'=';

        // One literal byte or a three-character escape. One column is reserved
        // for the '=' of a soft line break.
        let width = if literal { 1 } else { 3 };
        if column + width > MAX_QUOTED_PRINTABLE_LINE - 1 {
            out.push_str("=\r\n");
            column = 0;
        }
        if literal {
            // Only ASCII bytes are literal, so this slice is a char boundary.
            out.push_str(&input[index..=index]);
        } else {
            out.push('=');
            out.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            out.push(HEX_DIGITS[usize::from(byte & 0x0F)] as char);
        }
        column += width;
        index += 1;
    }
    out
}

fn hex_pair(high: u8, low: Option<&u8>) -> Option<u8> {
    let high = hex_digit(high)?;
    let low = hex_digit(*low?)?;
    Some(high * 16 + low)
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
    fn base64_tolerates_wrapping_and_missing_padding() {
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(decode_base64("SGVs\nbG8=").unwrap(), b"Hello");
        assert_eq!(decode_base64("SGVsbG8").unwrap(), b"Hello");
        // 76-column wrapping as produced by the renderer.
        let wrapped =
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz";
        assert_ne!(decode_base64(wrapped).unwrap(), Vec::new());
    }

    #[test]
    fn base64_rejects_alphabet_violations() {
        assert_eq!(
            decode_base64("SGVsbG8*"),
            Err(Error::InvalidBase64 { part: 0, offset: 7 })
        );
        assert_eq!(decode_base64("SGV sbG8=").err(), None); // whitespace is fine
        assert_eq!(
            decode_base64("===="),
            Err(Error::InvalidBase64 { part: 0, offset: 0 })
        );
    }

    /// The offset is a position in the text the caller still has: the decoder
    /// counts in the whitespace-free payload, so the offset is mapped back.
    #[test]
    fn base64_offset_counts_the_line_breaks_the_decoder_skipped() {
        assert_eq!(
            decode_base64("SGVs\r\nbG8=*"),
            Err(Error::InvalidBase64 {
                part: 0,
                offset: 10
            })
        );
        assert_eq!(
            decode_base64("QUJD\r\nQUJ*.QUJD"),
            Err(Error::InvalidBase64 { part: 0, offset: 9 })
        );
    }

    /// A payload that is only too short has no wrong byte, so the offset is the
    /// position just past its end — which is still a position in the input.
    #[test]
    fn base64_length_errors_point_past_the_end() {
        // Just inside the limit: two symbols are a complete quad.
        assert_eq!(decode_base64("AB").unwrap(), vec![0]);
        // One symbol short of a quad, wrapped the way a body arrives.
        assert_eq!(
            decode_base64("S\r\n"),
            Err(Error::InvalidBase64 { part: 0, offset: 3 })
        );
    }

    #[test]
    fn a_part_number_travels_with_the_error() {
        assert_eq!(
            decode_base64_in_part("SGVsbG8*", 7),
            Err(Error::InvalidBase64 { part: 7, offset: 7 })
        );
    }

    #[test]
    fn base64_output_is_bounded_by_input() {
        let input = "A".repeat(4096);
        let decoded = decode_base64(&input).unwrap();
        assert!(decoded.len() <= input.len());
    }

    #[test]
    fn quoted_printable_soft_breaks_and_escapes() {
        assert_eq!(decode_quoted_printable(""), b"");
        assert_eq!(decode_quoted_printable("a=20b"), b"a b");
        assert_eq!(decode_quoted_printable("a=\nb"), b"ab");
        assert_eq!(decode_quoted_printable("a=\rb"), b"ab");
        assert_eq!(
            decode_quoted_printable("Gr=C3=BC=C3=9Fe"),
            "Grüße".as_bytes()
        );
    }

    #[test]
    fn quoted_printable_malformed_input_is_kept_verbatim() {
        assert_eq!(decode_quoted_printable("a=ZZb"), b"a=ZZb");
        assert_eq!(decode_quoted_printable("a=Z"), b"a=Z");
        assert_eq!(decode_quoted_printable("trailing="), b"trailing");
        assert_eq!(decode_quoted_printable("="), b"");
    }

    #[test]
    fn quoted_printable_keeps_utf8_bytes_intact() {
        let text = "üñî";
        assert_eq!(decode_quoted_printable(text), text.as_bytes());
    }
}
