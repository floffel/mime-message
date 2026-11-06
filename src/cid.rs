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
//! # fn main() -> Result<(), mime_message::Error> {
//! let logo = Attachment::new("logo.png", "image/png", b"PNG".to_vec())
//!     .with_content_id("<logo@example.com>")?;
//! assert_eq!(logo.content_id.as_deref(), Some("logo@example.com"));
//!
//! let html = cid::rewrite("<img src=\"cid:logo@example.com\">", |reference| {
//!     (reference == "logo@example.com")
//!         .then(|| cid::data_uri(&logo.content_type, &logo.data))
//! });
//! assert!(html.starts_with("<img src=\"data:image/png;base64,"));
//! # Ok(())
//! # }
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use html_escape::decode_html_entities;

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

/// Validates and normalises a `Content-ID`.
///
/// The parser drops empty `Content-ID` fields, and the renderer rejects any
/// value that would not survive its angle brackets; construction uses the same
/// rule so a `cid:` part cannot count as inline and then fail at delivery time.
pub(crate) fn checked_content_id(raw: &str) -> Result<String> {
    let id = normalise(raw);
    if id.is_empty() {
        return Err(Error::EmptyHeader("Content-ID"));
    }
    let hostile = id.chars().find(|ch| is_hostile_id_char(*ch));
    match hostile {
        // `encode_utf8` always writes at least one byte, so the first slot of
        // the buffer is the leading byte of the character: nothing is guessed
        // and no byte of the input is invented.
        Some(ch) => {
            let mut encoded = [0_u8; 4];
            ch.encode_utf8(&mut encoded);
            Err(Error::control_value("Content-ID", encoded[0]))
        }
        None => Ok(id.to_string()),
    }
}

/// True for a character that would end a `Content-ID` before its closing `>`.
///
/// `<` and `>` would swallow the bracket that closes the `msg-id`, and NUL, a
/// control character or any whitespace would end the field there.
fn is_hostile_id_char(ch: char) -> bool {
    matches!(ch, '<' | '>' | '\0') || ch.is_control() || ch.is_whitespace()
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
/// angle brackets may still be present, as senders write both forms). HTML
/// character references inside URL positions are decoded before the resolver
/// sees them. Returning `None` leaves that reference exactly as it was. Only
/// URL positions are scanned: text, comments, script bodies and tag names are
/// untouched. A malformed angle-bracket reference that is not closed before
/// whitespace or another angle bracket is left unchanged.
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
/// Ordinary text that merely contains the letters is untouched. The rewriter
/// handles URL-bearing HTML attributes, `srcset` candidates, and CSS `url(...)`
/// functions in `style` attributes and `<style>` elements. It is still a small
/// HTML scanner rather than a full tokenizer, so unusual non-HTML dialects and
/// CSS escapes remain outside its scope.
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
    let candidates = find_candidates(html);
    let mut out = String::with_capacity(html.len());
    let mut copied = 0usize;

    for candidate in candidates {
        if candidate.start < copied {
            continue;
        }
        if let Some(replacement) = resolve(&candidate.reference) {
            out.push_str(&html[copied..candidate.start]);
            out.push_str(&replacement);
            copied = candidate.end;
        }
    }

    if copied == 0 {
        return html.to_string();
    }
    out.push_str(&html[copied..]);
    out
}

#[derive(Debug, Eq, PartialEq)]
struct Candidate {
    start: usize,
    end: usize,
    reference: String,
}

/// Finds `cid:` references in HTML URL positions without rewriting other text.
///
/// This is deliberately a small scanner, not a full HTML tokenizer. It covers
/// the places mail HTML puts image and link URLs: URL-bearing attributes,
/// `srcset` candidates, CSS `url(...)` functions in `style` attributes, and
/// CSS `url(...)` functions in `<style>` elements. It skips comments and raw
/// script text, and decodes character references in attribute-backed values
/// before handing a reference to the resolver. Other HTML syntax, including
/// CSS escapes and unusual non-HTML dialects, remains outside this scanner.
fn find_candidates(html: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    scan_document(html, &mut candidates);
    candidates
}

fn scan_document(html: &str, candidates: &mut Vec<Candidate>) {
    let bytes = html.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }

        if starts_with_ignore_ascii_case(html, index, "<!--") {
            index = skip_comment(html, index);
            continue;
        }
        if starts_with_ignore_ascii_case(html, index, "<!") || bytes.get(index + 1) == Some(&b'?') {
            index = skip_until_gt(html, index);
            continue;
        }
        if starts_with_ignore_ascii_case(html, index, "</") || !is_tag_start(bytes, index) {
            index = skip_until_gt(html, index);
            continue;
        }

        let Some(tag) = parse_start_tag(html, index, candidates) else {
            index += 1;
            continue;
        };

        if tag.name.eq_ignore_ascii_case("style") {
            let content_start = tag.end;
            let content_end = raw_text_end(html, content_start, "style");
            scan_css_range(html, content_start, content_end, false, candidates);
            index = content_end;
        } else if tag.name.eq_ignore_ascii_case("script") {
            index = raw_text_end(html, tag.end, "script");
        } else {
            index = tag.end;
        }
    }
}

struct StartTag<'a> {
    name: &'a str,
    end: usize,
}

fn parse_start_tag<'a>(
    html: &'a str,
    start: usize,
    candidates: &mut Vec<Candidate>,
) -> Option<StartTag<'a>> {
    let bytes = html.as_bytes();
    let mut index = start + 1;
    let name_start = index;

    while index < bytes.len() && is_tag_name_byte(bytes[index]) {
        index += 1;
    }
    if index == name_start {
        return None;
    }
    let name = &html[name_start..index];

    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b'>') {
            return Some(StartTag {
                name,
                end: index + 1,
            });
        }
        if bytes.get(index) == Some(&b'/') {
            index += 1;
            if bytes.get(index) == Some(&b'>') {
                return Some(StartTag {
                    name,
                    end: index + 1,
                });
            }
            continue;
        }
        if index >= bytes.len() {
            break;
        }

        let attr_start = index;
        while index < bytes.len() && !is_attribute_name_end(bytes[index]) {
            index += 1;
        }
        if index == attr_start {
            index += 1;
            continue;
        }
        let attr_name = &html[attr_start..index];

        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        let (value_start, value_end) = if let Some(&quote @ (b'"' | b'\'')) = bytes.get(index) {
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            // An unterminated quoted value would otherwise run to EOF and
            // swallow every later tag. Abandon this tag as malformed instead.
            if bytes.get(index) != Some(&quote) {
                return None;
            }
            let value_end = index;
            index += 1;
            (value_start, value_end)
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'>'
            {
                index += 1;
            }
            (value_start, index)
        };

        if is_url_attribute(attr_name) {
            scan_url_value(html, value_start, value_end, true, candidates);
        } else if is_srcset_attribute(attr_name) {
            scan_srcset_value(html, value_start, value_end, true, candidates);
        } else if is_style_attribute(attr_name) {
            scan_css_range(html, value_start, value_end, true, candidates);
        }
    }

    Some(StartTag {
        name,
        end: bytes.len(),
    })
}

fn is_url_attribute(name: &str) -> bool {
    [
        "action",
        "background",
        "cite",
        "classid",
        "codebase",
        "data",
        "formaction",
        "href",
        "icon",
        "longdesc",
        "manifest",
        "poster",
        "profile",
        "src",
        "usemap",
        "xlink:href",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn is_srcset_attribute(name: &str) -> bool {
    name.eq_ignore_ascii_case("srcset") || name.eq_ignore_ascii_case("imagesrcset")
}

fn is_style_attribute(name: &str) -> bool {
    name.eq_ignore_ascii_case("style")
}

fn scan_url_value(
    html: &str,
    start: usize,
    end: usize,
    decode_entities: bool,
    candidates: &mut Vec<Candidate>,
) {
    let bytes = html.as_bytes();
    let mut start = start;
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    add_candidate_from_raw(html, start, end, decode_entities, candidates);
}

fn scan_srcset_value(
    html: &str,
    start: usize,
    end: usize,
    decode_entities: bool,
    candidates: &mut Vec<Candidate>,
) {
    let bytes = html.as_bytes();
    let mut index = start;

    while index < end {
        while index < end && (bytes[index].is_ascii_whitespace() || bytes[index] == b',') {
            index += 1;
        }
        if index >= end {
            break;
        }

        let url_start = index;
        while index < end
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b','
            && bytes[index] != b'"'
            && bytes[index] != b'\''
            && bytes[index] != b'<'
            && bytes[index] != b'>'
        {
            index += 1;
        }
        add_candidate_from_raw(html, url_start, index, decode_entities, candidates);

        while index < end && bytes[index] != b',' {
            index += 1;
        }
        if index < end {
            index += 1;
        }
    }
}

fn scan_css_range(
    html: &str,
    start: usize,
    end: usize,
    decode_entities: bool,
    candidates: &mut Vec<Candidate>,
) {
    let bytes = html.as_bytes();
    let mut index = start;

    while index < end {
        if starts_with_ignore_ascii_case(html, index, "/*") {
            index = css_comment_end(html, index, end);
            continue;
        }
        if matches!(bytes.get(index), Some(b'"' | b'\'')) {
            index = css_string_end(html, index, end);
            continue;
        }
        if is_css_url_start(html, index, end) {
            index = parse_css_url(html, index, end, decode_entities, candidates);
            continue;
        }
        index += 1;
    }
}

fn is_css_url_start(html: &str, index: usize, end: usize) -> bool {
    let bytes = html.as_bytes();
    if index + 3 > end || !bytes[index..index + 3].eq_ignore_ascii_case(b"url") {
        return false;
    }
    if index > 0 && is_css_ident_byte(bytes[index - 1]) {
        return false;
    }

    let mut cursor = index + 3;
    while cursor < end && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    bytes.get(cursor) == Some(&b'(')
}

fn parse_css_url(
    html: &str,
    start: usize,
    end: usize,
    decode_entities: bool,
    candidates: &mut Vec<Candidate>,
) -> usize {
    let bytes = html.as_bytes();
    let mut index = start + 3;
    while index < end && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'(') {
        return index + 1;
    }
    index += 1;
    while index < end && bytes[index].is_ascii_whitespace() {
        index += 1;
    }

    if let Some(&quote @ (b'"' | b'\'')) =
        bytes.get(index).filter(|byte| matches!(byte, b'"' | b'\''))
    {
        index += 1;
        let value_start = index;
        while index < end && bytes[index] != quote {
            index += 1;
        }
        let value_end = index;
        add_candidate_from_raw(html, value_start, value_end, decode_entities, candidates);
        if bytes.get(index) == Some(&quote) {
            index += 1;
        }
        while index < end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b')') {
            index += 1;
        }
        return index;
    }

    let value_start = index;
    while index < end
        && !bytes[index].is_ascii_whitespace()
        && !matches!(bytes[index], b')' | b'"' | b'\'' | b'(')
    {
        index += 1;
    }
    add_candidate_from_raw(html, value_start, index, decode_entities, candidates);
    while index < end && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) == Some(&b')') {
        index += 1;
    }
    index
}

fn add_candidate_from_raw(
    html: &str,
    start: usize,
    end: usize,
    decode_entities: bool,
    candidates: &mut Vec<Candidate>,
) {
    let bytes = html.as_bytes();
    if start + 4 > end || !bytes[start..start + 4].eq_ignore_ascii_case(b"cid:") {
        return;
    }

    let reference_start = start + 4;
    let reference_end = reference_end(bytes, reference_start, end);
    if reference_start == reference_end {
        return;
    }

    let raw_reference = &html[reference_start..reference_end];
    let reference = if decode_entities {
        decode_html_entities(raw_reference).into_owned()
    } else {
        raw_reference.to_string()
    };
    if reference.is_empty() {
        return;
    }

    candidates.push(Candidate {
        start,
        end: reference_end,
        reference,
    });
}

fn skip_comment(html: &str, start: usize) -> usize {
    html[start + "<!--".len()..]
        .find("-->")
        .map_or(html.len(), |offset| {
            start + "<!--".len() + offset + "-->".len()
        })
}

fn skip_until_gt(html: &str, start: usize) -> usize {
    html[start..]
        .find('>')
        .map_or(html.len(), |offset| start + offset + 1)
}

fn raw_text_end(html: &str, start: usize, tag_name: &str) -> usize {
    let bytes = html.as_bytes();
    let mut index = start;
    while index + tag_name.len() + 2 <= bytes.len() {
        if bytes[index] == b'<'
            && bytes.get(index + 1) == Some(&b'/')
            && html[index + 2..]
                .get(..tag_name.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(tag_name))
        {
            let after = index + 2 + tag_name.len();
            if after == bytes.len() || bytes[after].is_ascii_whitespace() || bytes[after] == b'>' {
                return index;
            }
        }
        index += 1;
    }
    html.len()
}

fn css_comment_end(html: &str, start: usize, end: usize) -> usize {
    html[start + 2..end]
        .find("*/")
        .map_or(end, |offset| start + 2 + offset + 2)
}

fn css_string_end(html: &str, start: usize, end: usize) -> usize {
    let bytes = html.as_bytes();
    let quote = bytes[start];
    let mut index = start + 1;
    while index < end {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    end
}

fn starts_with_ignore_ascii_case(html: &str, start: usize, needle: &str) -> bool {
    html.get(start..start + needle.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
}

fn is_tag_start(bytes: &[u8], index: usize) -> bool {
    bytes.get(index + 1).is_some_and(u8::is_ascii_alphabetic)
}

fn is_tag_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-')
}

fn is_attribute_name_end(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'=' | b'/' | b'>')
}

fn is_css_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
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

/// End index of the reference that starts right after `cid:`.
///
/// `limit` is the end of the URL position holding the reference. An
/// angle-bracket reference must close with `>` before `limit`; an unterminated
/// one is left unchanged (returns `start`) so a malformed prefix never consumes
/// the surrounding markup.
fn reference_end(bytes: &[u8], start: usize, limit: usize) -> usize {
    if bytes.get(start) == Some(&b'<') {
        return match angle_reference_end(bytes, start, limit) {
            Some(end) => end,
            None => start,
        };
    }
    let mut end = start;
    while end < limit {
        if bytes[end] == b'&' {
            if let Some(entity_end) = html_entity_end(bytes, end, limit) {
                end = entity_end;
                continue;
            }
        }
        if !is_url_reference_byte(bytes[end]) || matches!(bytes[end], b'"' | b'\'' | b'<' | b'>') {
            break;
        }
        end += 1;
    }
    end
}

/// End index of a well-formed angle-bracket reference within `limit`, if any.
fn angle_reference_end(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut end = start + 1;
    while end < limit {
        let byte = bytes[end];
        if byte == b'>' {
            return Some(end + 1);
        }
        if byte == b'<' || byte.is_ascii_whitespace() || byte.is_ascii_control() {
            return None;
        }
        end += 1;
    }
    None
}

fn html_entity_end(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut index = start + 1;
    if bytes.get(index) == Some(&b'#') {
        index += 1;
        let digits_start = index;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'x' | b'X'))
        {
            index += 1;
            let hex_start = index;
            while index < limit && bytes[index].is_ascii_hexdigit() {
                index += 1;
            }
            if index == hex_start {
                return None;
            }
        } else {
            while index < limit && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if index == digits_start {
                return None;
            }
        }
    } else {
        let name_start = index;
        while index < limit && bytes[index].is_ascii_alphanumeric() {
            index += 1;
        }
        if index == name_start {
            return None;
        }
    }
    (bytes.get(index) == Some(&b';')).then_some(index + 1)
}

fn is_url_reference_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
                | b'@'
                | b'_'
                | b'~'
                | b'['
                | b']'
        )
        || byte >= 0x80
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::fmt::Write as _;

    fn cid_reference_text() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[A-Za-z0-9_.@+-]{1,20}")
            .expect("CID reference regex is valid")
    }

    fn rewrite_case() -> impl Strategy<Value = RewriteCase> {
        prop_oneof![
            proptest::string::string_regex("[^cC]{0,12}")
                .expect("literal regex is valid")
                .prop_map(RewriteCase::Literal),
            (cid_reference_text(), any::<bool>())
                .prop_map(|(text, unresolved)| { RewriteCase::Reference { text, unresolved } }),
        ]
    }

    #[derive(Clone, Debug)]
    enum RewriteCase {
        Literal(String),
        Reference { text: String, unresolved: bool },
    }

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
    fn rewrite_only_touches_url_positions() {
        let html = concat!(
            "<!-- <img src=\"cid:commented\"> -->",
            "<script>const x = \"cid:scripted\";</script>",
            "<p>cid:text</p>",
            "<a href=\"https://example.test/?next=cid:not-scheme\">x</a>",
            "<img data-cid=\"cid:not-url-attr\" src=\"cid:image\">",
            "<div data-cid=\"cid:not-url-attr\">x</div>",
        );
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            concat!(
                "<!-- <img src=\"cid:commented\"> -->",
                "<script>const x = \"cid:scripted\";</script>",
                "<p>cid:text</p>",
                "<a href=\"https://example.test/?next=cid:not-scheme\">x</a>",
                "<img data-cid=\"cid:not-url-attr\" src=\"[image]\">",
                "<div data-cid=\"cid:not-url-attr\">x</div>",
            )
        );
    }

    #[test]
    fn rewrite_decodes_character_references_in_urls() {
        let html = "<img src=\"cid:logo&#64;example.com\">";
        assert_eq!(
            rewrite(html, |reference| Some(format!("[{reference}]"))),
            "<img src=\"[logo@example.com]\">"
        );
    }

    #[test]
    fn rewrite_handles_srcset_url_candidates() {
        let html = "<img srcset=\"cid:a 1x, cid:b 2x, https://example.test/cid:c 3x\">";
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            "<img srcset=\"[a] 1x, [b] 2x, https://example.test/cid:c 3x\">"
        );
    }

    #[test]
    fn rewrite_handles_style_attribute_css_urls() {
        let html = "<div style=\"background:url('cid:a'); mask:url(cid:b)\"></div>";
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            "<div style=\"background:url('[a]'); mask:url([b])\"></div>"
        );
    }

    #[test]
    fn rewrite_does_not_split_unicode_punctuation_boundaries() {
        let html = "<img src=\"cid:a—b\"><img src=\"cid:c d\">";
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(rewritten, "<img src=\"[a—b]\"><img src=\"[c] d\">");
    }

    #[test]
    fn rewrite_handles_self_closing_tags_and_boolean_attributes() {
        let html = "<img hidden src=\"cid:image\"/><br data-x>cid:text";
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            "<img hidden src=\"[image]\"/><br data-x>cid:text"
        );
    }

    #[test]
    fn rewrite_handles_style_element_comments_and_resolved_strings() {
        let html = concat!(
            "<style>/* url(cid:commented) */",
            "a{background:url( cid:spaced )}",
            "b{background:URL(\"cid:quoted\")}",
            "c{background:url()}",
            "</style>"
        );
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            concat!(
                "<style>/* url(cid:commented) */",
                "a{background:url( [spaced] )}",
                "b{background:URL(\"[quoted]\")}",
                "c{background:url()}",
                "</style>"
            )
        );
    }

    #[test]
    fn rewrite_handles_entity_edge_cases_in_attributes() {
        let html = concat!(
            "<img src=\"cid:a&#x40;b\">",
            "<img src=\"cid:a&amp;b\">",
            "<img src=\"cid:a&bogus;b\">",
            "<img src=\"cid:a&#;b\">",
            "<img src=\"cid:\">",
        );
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            concat!(
                "<img src=\"[a@b]\">",
                "<img src=\"[a&b]\">",
                "<img src=\"[a&bogus;b]\">",
                "<img src=\"[a&#];b\">",
                "<img src=\"cid:\">",
            )
        );
    }

    #[test]
    fn rewrite_skips_bogus_and_unclosed_markup() {
        let html = concat!(
            "<?pi cid:processing?>",
            "<!DOCTYPE html>",
            "< not-a-tag cid:nope>",
            "</ broken cid:nope>",
            "<img src=\"cid:ok\"",
        );
        let rewritten = rewrite(html, |reference| Some(format!("[{reference}]")));
        assert_eq!(
            rewritten,
            concat!(
                "<?pi cid:processing?>",
                "<!DOCTYPE html>",
                "< not-a-tag cid:nope>",
                "</ broken cid:nope>",
                "<img src=\"[ok]\"",
            )
        );
    }

    #[test]
    fn rewrite_leaves_unresolved_and_malformed_references_alone() {
        assert_eq!(rewrite("cid:", |_| Some("x".into())), "cid:");
        assert_eq!(rewrite("cid: <", |_| Some("x".into())), "cid: <");
        assert_eq!(rewrite("xcid:a", |r| Some(format!("/{r}"))), "xcid:a");
        assert_eq!(
            rewrite("acid:cid:a", |r| Some(format!("/{r}"))),
            "acid:cid:a"
        );
        assert_eq!(rewrite("", |_| Some("x".into())), "");
    }

    #[test]
    fn rewrite_accepts_only_well_formed_angle_references() {
        assert_eq!(
            rewrite("<img src=\"cid:<abc>\">", |r| Some(format!("/{r}"))),
            "<img src=\"/<abc>\">"
        );
        assert_eq!(
            rewrite("<img src=\"cid:<abc\">", |r| Some(format!("/{r}"))),
            "<img src=\"cid:<abc\">"
        );
        assert_eq!(
            rewrite("<img src=\"cid:<abc def>\">", |r| Some(format!("/{r}"))),
            "<img src=\"cid:<abc def>\">"
        );
        assert_eq!(
            rewrite("<img src=\"cid:<abc<def>\">", |r| Some(format!("/{r}"))),
            "<img src=\"cid:<abc<def>\">"
        );
    }

    #[test]
    fn rewrite_preserves_valid_html_after_a_malformed_angle_reference() {
        let html = "<img src=\"cid:<broken\"><strong>after</strong>";
        assert_eq!(
            rewrite(html, |reference| Some(format!("[{reference}]"))),
            html
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

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn normalise_round_trips_trimmed_unicode_references(reference in any::<String>()) {
            let reference = reference.trim();
            prop_assume!(!reference.is_empty());
            prop_assume!(!reference.starts_with('<'));
            prop_assume!(!reference.starts_with('>'));
            prop_assume!(!reference.ends_with('<'));
            prop_assume!(!reference.ends_with('>'));
            let lower_scheme = format!("cid:{reference}");
            let upper_scheme = format!("CID:<{reference}>");

            prop_assert_eq!(normalise(&lower_scheme), reference);
            prop_assert_eq!(normalise(&upper_scheme), reference);
        }

        #[test]
        fn normalise_output_has_no_outer_junk(reference in any::<String>()) {
            let normalised = normalise(&reference);
            let starts_clean = normalised
                .chars()
                .next()
                .is_none_or(|ch| !ch.is_whitespace() && ch != '<' && ch != '>');
            let ends_clean = normalised
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_whitespace() && ch != '<' && ch != '>');

            prop_assert!(reference.contains(normalised));
            prop_assert!(starts_clean);
            prop_assert!(ends_clean);
        }

        #[test]
        fn data_uri_matches_validating_constructor_or_fallback(
            content_type in any::<String>(),
            data in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            if let Ok(uri) = try_data_uri(&content_type, &data) {
                prop_assert_eq!(data_uri(&content_type, &data), uri);
            } else {
                let fallback = format!(
                    "data:application/octet-stream;base64,{}",
                    STANDARD.encode(&data)
                );
                prop_assert_eq!(data_uri(&content_type, &data), fallback);
            }
        }

        #[test]
        fn try_data_uri_output_is_safe_and_round_trips_payload(
            content_type in any::<String>(),
            data in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            if let Ok(uri) = try_data_uri(&content_type, &data) {
                prop_assert!(uri.is_ascii(), "{uri:?}");
                prop_assert!(!uri.chars().any(char::is_whitespace), "{uri:?}");
                prop_assert!(!uri.chars().any(char::is_control), "{uri:?}");
                prop_assert!(
                    !uri
                        .chars()
                        .any(|ch| matches!(ch, '"' | '\'' | '<' | '>' | '&')),
                    "{uri:?}"
                );

                let (_, encoded) = uri
                    .rsplit_once(";base64,")
                    .expect("a data URI has a base64 marker");
                prop_assert_eq!(
                    STANDARD.decode(encoded).expect("output is standard base64"),
                    data,
                );
            }
        }

        #[test]
        fn rewrite_unresolved_preserves_html(html in any::<String>()) {
            let mut seen = Vec::new();
            let output = rewrite(&html, |reference| {
                seen.push(reference.to_string());
                None
            });

            prop_assert_eq!(&output, &html);
            for reference in &seen {
                prop_assert!(!reference.is_empty(), "empty callback reference");
                prop_assert!(html.contains(reference), "{reference:?} is not in {html:?}");
            }
        }

        #[test]
        fn rewrite_echoing_references_is_total(html in any::<String>()) {
            let mut seen = Vec::new();
            let output = rewrite(&html, |reference| {
                seen.push(reference.to_string());
                Some(reference.to_string())
            });

            for reference in &seen {
                prop_assert!(!reference.is_empty(), "empty callback reference");
            }
            prop_assert!(output.is_empty() == html.is_empty());
        }

        #[test]
        fn rewrite_ignores_empty_and_whitespace_references(gap in "[ \t\r\n]{1,8}") {
            let html = format!("<img src=\"cid:{gap}\">");
            let calls = std::cell::Cell::new(0usize);
            let output = rewrite(&html, |_| {
                calls.set(calls.get() + 1);
                Some("replacement".to_string())
            });

            prop_assert_eq!(calls.get(), 0);
            prop_assert_eq!(output, html);
        }

        #[test]
        fn rewrite_ignores_unterminated_angle_references(tail in "[^>\"']{0,20}") {
            // The URL position ends with the closing quote, so an angle-bracket
            // reference that never closes before it is left unchanged and never
            // hands the tail to the resolver.
            let html = format!("<img src=\"cid:<{tail}\">");
            let calls = std::cell::Cell::new(0usize);
            let output = rewrite(&html, |_| {
                calls.set(calls.get() + 1);
                Some("replacement".to_string())
            });

            prop_assert_eq!(calls.get(), 0);
            prop_assert_eq!(output, html);
        }

        #[test]
        fn rewrite_calls_resolver_once_in_reference_order(
            cases in prop::collection::vec(rewrite_case(), 0..8),
        ) {
            let mut html = String::new();
            let mut expected = String::new();
            let mut expected_references: Vec<(String, bool)> = Vec::new();

            for case in cases {
                match case {
                    RewriteCase::Literal(text) => {
                        write!(html, "<span>{text}</span>").expect("writing to a String cannot fail");
                        write!(expected, "<span>{text}</span>")
                            .expect("writing to a String cannot fail");
                    }
                    RewriteCase::Reference { text, unresolved } => {
                        write!(html, "<img src=\"cid:{text}\">")
                            .expect("writing to a String cannot fail");
                        if unresolved {
                            write!(expected, "<img src=\"cid:{text}\">")
                                .expect("writing to a String cannot fail");
                        } else {
                            write!(expected, "<img src=\"[{text}]\">")
                                .expect("writing to a String cannot fail");
                        }
                        expected_references.push((text, unresolved));
                    }
                }
            }

            let index = std::cell::Cell::new(0usize);
            let output = rewrite(&html, |reference| {
                let current = index.get();
                assert!(
                    current < expected_references.len(),
                    "unexpected reference {reference:?}"
                );
                let (expected_reference, unresolved) = &expected_references[current];
                assert_eq!(reference, expected_reference.as_str());
                index.set(current + 1);
                (!*unresolved).then(|| format!("[{expected_reference}]"))
            });

            prop_assert_eq!(index.get(), expected_references.len());
            prop_assert_eq!(output, expected);
        }
    }
}
