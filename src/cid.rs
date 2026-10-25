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
#[must_use]
pub fn data_uri(content_type: &str, data: &[u8]) -> String {
    format!("data:{content_type};base64,{}", STANDARD.encode(data))
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
}
