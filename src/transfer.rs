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
/// the base64 alphabet or impossible padding.
pub fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let mut compact = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        if !byte.is_ascii_whitespace() {
            compact.push(byte);
        }
    }
    LENIENT.decode(&compact).map_err(|_| Error::InvalidBase64)
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
        assert!(!decode_base64(wrapped).unwrap().is_empty());
    }

    #[test]
    fn base64_rejects_alphabet_violations() {
        assert_eq!(decode_base64("SGVsbG8*"), Err(Error::InvalidBase64));
        assert_eq!(decode_base64("SGV sbG8=").err(), None); // whitespace is fine
        assert_eq!(decode_base64("===="), Err(Error::InvalidBase64));
        assert_eq!(decode_base64("S"), Err(Error::InvalidBase64));
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
