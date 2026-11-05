//! Inline content: `Content-ID` parts and `cid:` references.
//!
//! A `multipart/related` message carries its images as parts with a
//! `Content-ID`, and the HTML body points at them with `cid:` URLs
//! (RFC 2392). Nothing here touches the network: the caller decides whether a
//! reference becomes a `data:` URI ([`data_uri`]), a link into their own
//! webmail, or stays as it is.
//!
//! ```
//! use mime_message::{cid, Attachment};
//!
//! let logo = Attachment::new("logo.png", "image/png", b"PNG".to_vec())
//!     .with_content_id("<logo@example.com>");
//! assert_eq!(logo.content_id.as_deref(), Some("logo@example.com"));
//!
//! let html = cid::rewrite("<img src=\"cid:logo@example.com\">", |reference| {
//!     (reference == "logo@example.com")
//!         .then(|| cid::data_uri(&logo.content_type, &logo.data))
//! });
//! assert!(html.starts_with("<img src=\"data:image/png;base64,"));
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{Error, Result};
use crate::parse::parse_media_type;

/// Strips the `cid:` scheme and surrounding angle brackets from a reference.
///
/// The result is the bare `Content-ID`, which is what
/// [`Attachment::content_id`](crate::Attachment::content_id) holds. Values
/// without a scheme are normalised the same way, so a caller can pass either
/// form.
///
/// ```
/// use mime_message::cid;
///
/// assert_eq!(cid::normalise("cid:logo"), "logo");
/// assert_eq!(cid::normalise("CID:<logo@example.com>"), "logo@example.com");
/// assert_eq!(cid::normalise(" logo "), "logo");
/// ```
#[must_use]
pub fn normalise(reference: &str) -> &str {
    let mut text = reference.trim();
    if text.len() >= 4 && text.is_char_boundary(4) && text[..4].eq_ignore_ascii_case("cid:") {
        text = text[4..].trim();
    }
    text.trim_matches(|ch| ch == '<' || ch == '>').trim()
}

/// Builds a `data:` URI for one part.
///
/// ```
/// use mime_message::cid;
///
/// assert_eq!(cid::data_uri("image/png", b"hi"), "data:image/png;base64,aGk=");
/// ```
///
/// A `Content-Type` that is not a media type falls back to
/// `application/octet-stream`, so the result is still a URI a browser can
/// load. Use [`try_data_uri`] when the caller needs to distinguish a fallback
/// from the content type that was requested. The returned string is a raw URI,
/// not HTML-escaped; when inserting it into HTML, put it in a quoted attribute
/// or otherwise escape it for the insertion context.
#[must_use]
pub fn data_uri(content_type: &str, data: &[u8]) -> String {
    match try_data_uri(content_type, data) {
        Ok(uri) => uri,
        Err(_) => format!(
            "data:application/octet-stream;base64,{}",
            STANDARD.encode(data)
        ),
    }
}

/// Builds a `data:` URI for one part, rejecting an invalid `content_type`.
///
/// The value must be an RFC media type: `type/subtype` with optional
/// parameters. Parameters are parsed and re-rendered with percent encoding for
/// the `data:` URI, so a quote or control byte in a parameter cannot terminate
/// an HTML attribute when the URI is later inserted into quoted markup.
/// Control characters and HTML delimiter characters in the type, subtype or
/// parameter name are rejected rather than escaped.
///
/// ```
/// use mime_message::cid;
///
/// assert_eq!(
///     cid::try_data_uri("text/plain; name=\"x y\"", b"hi").unwrap(),
///     "data:text/plain;name=x%20y;base64,aGk="
/// );
/// assert!(cid::try_data_uri("text/plain; name=\"x\"\" onerror=\"x", b"hi").is_err());
/// ```
///
/// # Errors
///
/// Returns [`Error::InvalidContentType`] when `content_type` is not a media
/// type, or when a parameter name or value contains bytes that cannot be
/// safely rendered in a `data:` URI.
pub fn try_data_uri(content_type: &str, data: &[u8]) -> Result<String> {
    if content_type.chars().any(char::is_control) {
        return Err(invalid_content_type(content_type));
    }
    if !parameters_are_safe(content_type) {
        return Err(invalid_content_type(content_type));
    }
    let media = parse_media_type(content_type, 0)?;
    if media
        .kind
        .bytes()
        .chain(media.subtype.bytes())
        .any(is_unsafe_data_uri_delimiter)
    {
        return Err(invalid_content_type(content_type));
    }
    let mut uri = format!("data:{}", media.essence());
    for (name, value) in &media.params {
        if name.bytes().any(|byte| !is_safe_parameter_name_byte(byte)) {
            return Err(invalid_content_type(content_type));
        }
        uri.push(';');
        uri.push_str(name);
        uri.push('=');
        uri.push_str(&percent_encode_data_parameter(value));
    }
    uri.push_str(";base64,");
    uri.push_str(&STANDARD.encode(data));
    Ok(uri)
}

/// Rewrites every `cid:` reference in `html` through `resolve`.
///
/// `resolve` receives the reference without the `cid:` scheme (surrounding
/// angle brackets may still be present, as senders write both forms). Returning
/// `None` leaves that reference exactly as it was.
///
/// ```
/// use mime_message::cid;
///
/// let html = "<img src=\"cid:a\"> <a href=\"cid:b\">b</a> <img src=\"cid:missing\">";
/// let rewritten = cid::rewrite(html, |reference| {
///     (reference != "missing").then(|| format!("/inline/{reference}.png"))
/// });
/// assert_eq!(
///     rewritten,
///     "<img src=\"/inline/a.png\"> <a href=\"/inline/b.png\">b</a> <img src=\"cid:missing\">",
/// );
/// ```
///
/// Ordinary text that merely contains the letters is untouched: a reference has
/// to start at a word boundary.
///
/// ```
/// use mime_message::cid;
///
/// assert_eq!(cid::rewrite("acid:not-a-cid", |_| Some("x".to_string())), "acid:not-a-cid");
/// ```
#[must_use]
pub fn rewrite<F>(html: &str, mut resolve: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    const SCHEME: &[u8] = b"cid:";
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut copied = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        let scheme_here = index + SCHEME.len() <= bytes.len()
            && bytes[index..index + SCHEME.len()].eq_ignore_ascii_case(SCHEME)
            && (index == 0 || !is_word_byte(bytes[index - 1]));
        if !scheme_here {
            index += 1;
            continue;
        }
        let start = index + SCHEME.len();
        let end = reference_end(bytes, start);
        let reference = &html[start..end];
        if reference.is_empty() {
            index = start;
            continue;
        }
        match resolve(reference) {
            Some(replacement) => {
                out.push_str(&html[copied..index]);
                out.push_str(&replacement);
                copied = end;
                index = end;
            }
            None => index = end,
        }
    }

    out.push_str(&html[copied..]);
    out
}

/// Percent-encodes a data URI parameter value.
fn percent_encode_data_parameter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn is_unsafe_data_uri_delimiter(byte: u8) -> bool {
    matches!(byte, b'"' | b'\'' | b'<' | b'>' | b'&')
}

fn is_safe_parameter_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// A stricter parameter scan than the permissive parser.
///
/// Reading mail tolerates garbage around `Content-Type` parameters; building a
/// URI does not. This checks the raw value so a malformed parameter cannot be
/// skipped by the parser and then reappear as literal text.
fn parameters_are_safe(content_type: &str) -> bool {
    let Some((_, raw)) = content_type.split_once(';') else {
        return true;
    };
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b';') {
            index += 1;
        }
        if index >= bytes.len() {
            return true;
        }
        let name_start = index;
        while index < bytes.len() && bytes[index] != b'=' && bytes[index] != b';' {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            return false;
        }
        let name = raw[name_start..index].trim();
        if name.is_empty() || !name.bytes().all(is_safe_parameter_name_byte) {
            return false;
        }
        index += 1;
        if bytes.get(index) == Some(&b'"') {
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => {
                        index += 1;
                        if index >= bytes.len() || bytes[index].is_ascii_control() {
                            return false;
                        }
                        index += 1;
                    }
                    b'"' => {
                        index += 1;
                        break;
                    }
                    byte if byte.is_ascii_control() => return false,
                    _ => index += 1,
                }
            }
            if bytes.get(index - 1) != Some(&b'"') {
                return false;
            }
        } else {
            while index < bytes.len() && bytes[index] != b';' {
                if bytes[index].is_ascii_control() || is_unsafe_data_uri_delimiter(bytes[index]) {
                    return false;
                }
                index += 1;
            }
        }
    }
    true
}

fn invalid_content_type(content_type: &str) -> Error {
    Error::InvalidContentType {
        part: 0,
        text: crate::truncate(content_type, 120),
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Bytes that make a preceding `cid:` part of a longer word.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte >= 0x80
}

/// End index of the reference that starts right after `cid:`.
fn reference_end(bytes: &[u8], start: usize) -> usize {
    if bytes.get(start) == Some(&b'<') {
        return match bytes[start..].iter().position(|byte| *byte == b'>') {
            Some(offset) => start + offset + 1,
            None => bytes.len(),
        };
    }
    let mut end = start;
    while end < bytes.len()
        && !matches!(
            bytes[end],
            b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'(' | b')' | b'<' | b'>' | b',' | b';'
        )
    {
        end += 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_handles_both_forms_and_junk() {
        assert_eq!(normalise(""), "");
        assert_eq!(normalise("cid:"), "");
        assert_eq!(normalise("cid:<a@b>"), "a@b");
        assert_eq!(normalise("<>"), "");
        assert_eq!(normalise("  cid:  a  "), "a");
        assert_eq!(normalise("xcid:a"), "xcid:a");
    }

    #[test]
    fn rewrite_covers_attributes_and_css_urls() {
        let html = "<td background=\"cid:a\"><style>x{background:url(cid:b)}</style></td>";
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            "<td background=\"[a]\"><style>x{background:url([b])}</style></td>"
        );
    }

    #[test]
    fn rewrite_leaves_unresolved_and_malformed_references_alone() {
        assert_eq!(rewrite("cid:", |_| Some("x".into())), "cid:");
        assert_eq!(rewrite("cid: <", |_| Some("x".into())), "cid: <");
        assert_eq!(rewrite("xcid:a", |r| Some(format!("/{r}"))), "xcid:a");
        // A scheme-looking prefix is a boundary: `acid:cid:a` has a real `cid:`.
        assert_eq!(rewrite("acid:cid:a", |r| Some(format!("/{r}"))), "acid:/a");
        assert_eq!(rewrite("", |_| Some("x".into())), "");
    }

    #[test]
    fn rewrite_handles_unterminated_angle_reference() {
        assert_eq!(
            rewrite("<img src=cid:<abc", |r| Some(format!("/{r}"))),
            "<img src=/<abc"
        );
    }

    #[test]
    fn rewrite_is_byte_safe_for_multibyte_text() {
        let html = "Grüße <img src=\"cid:bölk\">";
        assert_eq!(
            rewrite(html, |r| Some(format!("/{r}"))),
            "Grüße <img src=\"/bölk\">"
        );
    }

    #[test]
    fn data_uri_uses_standard_base64() {
        assert_eq!(data_uri("text/plain", b""), "data:text/plain;base64,");
        assert_eq!(
            data_uri("image/png", &[0xff, 0x00]),
            "data:image/png;base64,/wA="
        );
    }

    #[test]
    fn try_data_uri_rejects_invalid_media_types() {
        assert!(try_data_uri("text/plain; name=\"x\"\" onerror=\"x", b"hi").is_err());
        assert!(try_data_uri("image/png\r\nX: y", b"hi").is_err());
        assert!(try_data_uri("image/png; name=\"x\\\r\n y\"", b"hi").is_err());
        assert!(try_data_uri("image/p'ng", b"hi").is_err());
        assert!(try_data_uri("image/png; x'=y", b"hi").is_err());
        assert!(try_data_uri("text/plain; name=\"x\"", b"hi").is_ok());
    }

    #[test]
    fn try_data_uri_percent_encodes_parameters() {
        assert_eq!(
            try_data_uri("text/plain; name=\"x y&z\"", b"hi").unwrap(),
            "data:text/plain;name=x%20y%26z;base64,aGk="
        );
    }

    #[test]
    fn data_uri_falls_back_for_invalid_media_types() {
        assert_eq!(
            data_uri("text/plain; name=\"x\"\" onerror=\"x", b"hi"),
            "data:application/octet-stream;base64,aGk="
        );
    }
}
