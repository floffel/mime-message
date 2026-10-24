//! RFC 5322 + MIME parsing.
//!
//! The parser turns wire bytes (as `&str`) into a [`Message`]: headers are
//! unfolded, RFC 2047 decoded, addresses parsed (comments, quoted display names
//! and groups included), `Content-Type` parameters interpreted (RFC 2231
//! extended parameters too), transfer encodings decoded and `multipart/*` trees
//! walked recursively under a depth, part-count and size budget.
//!
//! Everything here is pure: no I/O, no globals, no interior mutability.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::{charset, rfc2047, transfer, Attachment, Mailbox, Message};

/// Longest header line (after unfolding) accepted, in bytes.
const MAX_HEADER_LINE: usize = 8 * 1024;

/// Hard limits applied while parsing.
///
/// The defaults are generous for real mail and small enough that a malicious
/// message cannot exhaust memory: 32 levels of nesting, 1000 parts, 64 KiB of
/// headers, 8 MiB per decoded body.
///
/// The struct is `#[non_exhaustive]`: start from [`Limits::default`] and adjust
/// individual fields.
///
/// ```
/// use mime_message::{parse_with_limits, Limits};
///
/// let mut limits = Limits::default();
/// limits.max_depth = 2;
///
/// // A three-level multipart message is rejected instead of recursing.
/// let nested = concat!(
///     "From: a@example.com\r\n",
///     "Content-Type: multipart/mixed; boundary=a\r\n\r\n",
///     "--a\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n",
///     "--b\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n",
///     "--c\r\n\r\nhi\r\n--c--\r\n--b--\r\n--a--\r\n",
/// );
/// assert!(parse_with_limits(nested, &limits).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum `multipart/*` nesting depth (the top-level entity is depth 0).
    pub max_depth: usize,
    /// Maximum number of MIME entities, the top-level one included.
    pub max_parts: usize,
    /// Maximum total size of a header block, in bytes.
    pub max_header_bytes: usize,
    /// Maximum length of one header line, in bytes.
    pub max_header_line_bytes: usize,
    /// Maximum number of header fields in one block.
    pub max_headers: usize,
    /// Maximum size of one undecoded *and* decoded body, in bytes.
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_parts: 1000,
            max_header_bytes: 64 * 1024,
            max_header_line_bytes: MAX_HEADER_LINE,
            max_headers: 1000,
            max_body_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Parses an RFC 5322 / MIME message with the default [`Limits`].
///
/// ```
/// use mime_message::parse;
///
/// let raw = concat!(
///     "From: \"Shop\" <shop@example.com>\r\n",
///     "To: kunde@example.com, \"Zweiter\" <zwei@example.com>\r\n",
///     "Subject: =?UTF-8?B?R3LDvMOfZQ==?=\r\n",
///     "Content-Type: text/plain; charset=utf-8\r\n",
///     "\r\n",
///     "Hallo\r\n",
/// );
/// let message = parse(raw)?;
/// assert_eq!(message.from.address, "shop@example.com");
/// assert_eq!(message.from.name.as_deref(), Some("Shop"));
/// assert_eq!(message.to.len(), 2);
/// assert_eq!(message.subject, "Grüße");
/// assert_eq!(message.body, "Hallo\r\n");
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// # Errors
///
/// Returns a typed [`Error`] for anything that is not a message we can safely
/// hand to a renderer: no header block, a missing `From:`, malformed headers or
/// addresses, unsupported transfer encodings, truncated multipart bodies, unsafe
/// attachment filenames, and every [`Limits`] violation.
#[must_use = "the parsed message is the result"]
pub fn parse(raw: &str) -> Result<Message> {
    parse_with_limits(raw, &Limits::default())
}

/// Parses a message with explicit [`Limits`].
///
/// ```
/// use mime_message::{parse_with_limits, Limits};
///
/// let mut limits = Limits::default();
/// limits.max_body_bytes = 4;
///
/// let raw = "From: a@example.com\r\n\r\n0123456789";
/// assert!(parse_with_limits(raw, &limits).is_err());
/// ```
///
/// # Errors
///
/// As [`parse`], plus [`Error::LimitExceeded`] when a budget is exhausted.
#[must_use = "the parsed message is the result"]
pub fn parse_with_limits(raw: &str, limits: &Limits) -> Result<Message> {
    Parser { limits, parts: 0 }.parse_message(raw)
}

struct Parser<'limits> {
    limits: &'limits Limits,
    parts: usize,
}

impl Parser<'_> {
    fn parse_message(&mut self, raw: &str) -> Result<Message> {
        let (head, body) = split_head(raw);
        if head.trim().is_empty() {
            return Err(Error::EmptyMessage);
        }
        let headers = parse_header_block(head, self.limits)?;

        let from = parse_address_list(
            headers.get("From").ok_or(Error::EmptyHeader("From"))?,
            "From",
        )?
        .into_iter()
        .next()
        .ok_or(Error::EmptyHeader("From"))?;

        let to = parse_joined_addresses(&headers, "To")?;
        let cc = parse_joined_addresses(&headers, "Cc")?;
        let subject = header_text(&headers, "Subject")?.unwrap_or_default();
        let date = header_text(&headers, "Date")?;
        let message_id = header_text(&headers, "Message-ID")?;

        let entity = self.parse_entity(&headers, body, 0)?;
        let mut flat = Flat::default();
        flatten(entity, &mut flat);

        Ok(Message {
            from,
            to,
            cc,
            subject,
            body: flat.body,
            html_body: flat.html,
            date,
            message_id,
            attachments: flat.attachments,
        })
    }

    fn parse_entity(&mut self, headers: &Headers, body: &str, depth: usize) -> Result<Entity> {
        if depth >= self.limits.max_depth {
            return Err(Error::LimitExceeded {
                what: "nesting depth",
                limit: self.limits.max_depth,
            });
        }
        self.parts += 1;
        if self.parts > self.limits.max_parts {
            return Err(Error::LimitExceeded {
                what: "part count",
                limit: self.limits.max_parts,
            });
        }

        let media = match headers.unique("Content-Type")? {
            Some(value) => parse_media_type(value)?,
            None => MediaType::text_plain(),
        };

        let disposition = headers.get("Content-Disposition").map(parse_parameterized);
        let filename = disposition
            .as_ref()
            .and_then(|(_, params)| params.get("filename").cloned())
            .or_else(|| media.params.get("name").cloned());
        if let Some(name) = &filename {
            check_filename(name)?;
        }

        let encoding = Encoding::parse(headers.unique("Content-Transfer-Encoding")?)?;

        let content = if media.kind == "multipart" {
            let boundary = media
                .param("boundary")
                .ok_or(Error::MissingBoundary)?
                .to_string();
            let text = self.decoded_text(body, encoding)?;
            let raw_parts = split_multipart(&text, &boundary)?;
            let mut children = Vec::with_capacity(raw_parts.len());
            for part in raw_parts {
                let (part_head, part_body) = split_head(part);
                let part_headers = parse_header_block(part_head, self.limits)?;
                children.push(self.parse_entity(&part_headers, part_body, depth + 1)?);
            }
            Content::Multipart(children)
        } else {
            Content::Body(self.decode_transfer(body, encoding)?)
        };

        Ok(Entity {
            media,
            disposition: disposition.map(|(kind, _)| kind),
            filename,
            content,
        })
    }

    fn check_body_size(&self, size: usize) -> Result<()> {
        if size > self.limits.max_body_bytes {
            return Err(Error::LimitExceeded {
                what: "body bytes",
                limit: self.limits.max_body_bytes,
            });
        }
        Ok(())
    }

    fn decode_transfer(&self, body: &str, encoding: Encoding) -> Result<Vec<u8>> {
        self.check_body_size(body.len())?;
        let bytes = match encoding {
            Encoding::Identity => body.as_bytes().to_vec(),
            Encoding::Base64 => transfer::decode_base64(body)?,
            Encoding::QuotedPrintable => transfer::decode_quoted_printable(body),
        };
        // Decoding must never amplify: base64 shrinks, QP shrinks or matches.
        self.check_body_size(bytes.len())?;
        Ok(bytes)
    }

    fn decoded_text<'a>(&self, body: &'a str, encoding: Encoding) -> Result<Cow<'a, str>> {
        match encoding {
            Encoding::Identity => {
                self.check_body_size(body.len())?;
                Ok(Cow::Borrowed(body))
            }
            _ => Ok(Cow::Owned(
                String::from_utf8_lossy(&self.decode_transfer(body, encoding)?).into_owned(),
            )),
        }
    }
}

/// A parsed MIME entity before it is flattened into a [`Message`].
struct Entity {
    media: MediaType,
    disposition: Option<String>,
    filename: Option<String>,
    content: Content,
}

enum Content {
    Body(Vec<u8>),
    Multipart(Vec<Entity>),
}

#[derive(Default)]
struct Flat {
    body: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
    body_seen: bool,
}

/// Flattens the entity tree: first text part becomes the body, `text/html`
/// becomes [`Message::html_body`], everything else becomes an attachment.
fn flatten(entity: Entity, out: &mut Flat) {
    match entity.content {
        Content::Multipart(children) => {
            for child in children {
                flatten(child, out);
            }
        }
        Content::Body(bytes) => {
            let is_text = entity.media.kind == "text";
            let is_named =
                entity.filename.is_some() || entity.disposition.as_deref() == Some("attachment");
            if is_text && !is_named {
                let text = charset::decode(&bytes, entity.media.charset());
                if entity.media.subtype == "html" {
                    if out.html.is_none() {
                        out.html = Some(text);
                        return;
                    }
                } else if !out.body_seen {
                    out.body = text;
                    out.body_seen = true;
                    return;
                }
            }
            let filename = entity
                .filename
                .unwrap_or_else(|| format!("part-{}", out.attachments.len() + 1));
            out.attachments.push(Attachment {
                filename,
                content_type: entity.media.essence(),
                data: bytes,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Header block
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// All values of `name` joined with `", "` (duplicate `To:` is legal-ish).
    fn get_joined(&self, name: &str) -> Option<String> {
        let mut values = self
            .entries
            .iter()
            .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .peekable();
        values.peek()?;
        let mut joined = String::new();
        for (index, value) in values.enumerate() {
            if index > 0 {
                joined.push_str(", ");
            }
            joined.push_str(value);
        }
        Some(joined)
    }

    /// Returns the single value of `name`, rejecting duplicates.
    ///
    /// Duplicate `Content-Type` / `Content-Transfer-Encoding` headers are how
    /// content-type smuggling starts, so they are a hard error rather than
    /// "last one wins".
    fn unique(&self, name: &'static str) -> Result<Option<&str>> {
        let mut found: Option<&str> = None;
        for (candidate, value) in &self.entries {
            if candidate.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return Err(Error::DuplicateHeader(name.to_string()));
                }
                found = Some(value);
            }
        }
        Ok(found)
    }
}

fn parse_header_block(block: &str, limits: &Limits) -> Result<Headers> {
    let mut headers = Headers::default();
    let mut total = 0usize;
    let mut rest = block;

    while !rest.is_empty() {
        let (line, next) = next_line(rest);
        total = total.saturating_add(line.len() + 2);
        if total > limits.max_header_bytes {
            return Err(Error::LimitExceeded {
                what: "header bytes",
                limit: limits.max_header_bytes,
            });
        }
        if line.len() > limits.max_header_line_bytes {
            return Err(Error::LimitExceeded {
                what: "header line length",
                limit: limits.max_header_line_bytes,
            });
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            match headers.entries.last_mut() {
                Some((_, value)) => {
                    value.push(' ');
                    value.push_str(line.trim());
                }
                None => return Err(Error::MalformedHeader(truncate(line, 120))),
            }
        } else {
            let Some(colon) = line.find(':') else {
                return Err(Error::MalformedHeader(truncate(line, 120)));
            };
            let name = &line[..colon];
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err(Error::MalformedHeader(truncate(line, 120)));
            }
            headers
                .entries
                .push((name.to_string(), line[colon + 1..].trim().to_string()));
            if headers.entries.len() > limits.max_headers {
                return Err(Error::LimitExceeded {
                    what: "header count",
                    limit: limits.max_headers,
                });
            }
        }
        rest = next;
    }

    for (name, value) in &headers.entries {
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F)
        {
            return Err(Error::ControlCharacter(name.clone()));
        }
    }

    Ok(headers)
}

/// Splits `raw` into the header block and the body at the first blank line.
fn split_head(raw: &str) -> (&str, &str) {
    let mut rest = raw;
    let mut offset = 0usize;
    loop {
        let (line, next) = next_line(rest);
        if line.is_empty() {
            let body_start = offset + (rest.len() - next.len());
            return (&raw[..offset], &raw[body_start..]);
        }
        if next.is_empty() {
            // No blank line: the whole input is headers, there is no body.
            return (raw, "");
        }
        offset += rest.len() - next.len();
        rest = next;
    }
}

/// Returns `(line, rest)` where `rest` starts after the line terminator.
///
/// Accepts CRLF, bare LF and bare CR. Never panics: indices always land on
/// ASCII byte boundaries.
fn next_line(input: &str) -> (&str, &str) {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => return (&input[..index], &input[index + 1..]),
            b'\r' => {
                if bytes.get(index + 1) == Some(&b'\n') {
                    return (&input[..index], &input[index + 2..]);
                }
                return (&input[..index], &input[index + 1..]);
            }
            _ => index += 1,
        }
    }
    (input, "")
}

fn header_text(headers: &Headers, name: &'static str) -> Result<Option<String>> {
    headers
        .get(name)
        .map(|raw| {
            // Trimming after decoding matters: an encoded-word can end in
            // whitespace that the raw header value did not show, and leading
            // and trailing whitespace is not significant in a header.
            let decoded = rfc2047::decode(raw).trim().to_string();
            check_header_value(name, &decoded)?;
            Ok(decoded)
        })
        .transpose()
}

fn check_header_value(name: &'static str, value: &str) -> Result<()> {
    let dangerous = value.chars().any(|ch| {
        matches!(ch, '\r' | '\n' | '\0' | '\u{85}' | '\u{2028}' | '\u{2029}')
            || (ch.is_control() && ch != '\t')
    });
    if dangerous {
        return Err(Error::HeaderInjection(name));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

fn parse_joined_addresses(headers: &Headers, name: &'static str) -> Result<Vec<Mailbox>> {
    match headers.get_joined(name) {
        Some(value) => parse_address_list(&value, name),
        None => Ok(Vec::new()),
    }
}

fn parse_address_list(raw: &str, header: &'static str) -> Result<Vec<Mailbox>> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut token_start = 0usize;
    let mut in_group = false;
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_quoted(raw, index),
            b'(' => index = skip_comment(raw, index),
            b'<' => index = skip_angle(raw, index),
            b':' if !in_group => {
                in_group = true;
                index += 1;
                token_start = index;
            }
            b';' if in_group => {
                push_address(&raw[token_start..index], header, &mut out)?;
                in_group = false;
                index += 1;
                token_start = index;
            }
            b',' => {
                push_address(&raw[token_start..index], header, &mut out)?;
                index += 1;
                token_start = index;
            }
            _ => index += 1,
        }
    }
    push_address(&raw[token_start..], header, &mut out)?;
    Ok(out)
}

fn push_address(raw: &str, header: &'static str, out: &mut Vec<Mailbox>) -> Result<()> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    out.push(parse_single_address(raw, header)?);
    Ok(())
}

fn parse_single_address(raw: &str, header: &'static str) -> Result<Mailbox> {
    let fallback_name = first_comment(raw);
    let without_comments = strip_comments(raw);
    let text = without_comments.trim();

    let (display, address) = match angle_open(text) {
        Some(open) => {
            let Some(close_rel) = text[open..].find('>') else {
                return Err(Error::InvalidMailbox(truncate(raw, 120)));
            };
            let close = open + close_rel;
            (text[..open].trim(), text[open + 1..close].trim())
        }
        None => ("", text),
    };

    validate_address(address)?;

    if display.is_empty() {
        if let Some(name) = fallback_name {
            let name = rfc2047::decode(name.trim());
            check_header_value(header, &name)?;
            if !name.is_empty() {
                return Ok(Mailbox {
                    name: Some(name),
                    address: address.to_string(),
                });
            }
        }
        return Ok(Mailbox {
            name: None,
            address: address.to_string(),
        });
    }

    let name = rfc2047::decode(&unquote(display));
    check_header_value(header, &name)?;
    let name = name.trim();
    Ok(Mailbox {
        name: if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        },
        address: address.to_string(),
    })
}

fn validate_address(address: &str) -> Result<()> {
    let invalid = || Error::InvalidMailbox(truncate(address, 120));
    if address.is_empty() || address.contains(['<', '>']) {
        return Err(invalid());
    }
    let Some((local, domain)) = address.rsplit_once('@') else {
        return Err(invalid());
    };
    if local.is_empty() || domain.is_empty() {
        return Err(invalid());
    }
    let quoted_local = local.len() >= 2 && local.starts_with('"') && local.ends_with('"');
    let bare_local = if quoted_local {
        &local[1..local.len() - 1]
    } else {
        local
    };
    if bare_local.is_empty() || bare_local.chars().any(char::is_control) {
        return Err(invalid());
    }
    if !quoted_local && (bare_local.chars().any(char::is_whitespace) || bare_local.contains('@')) {
        return Err(invalid());
    }
    if domain
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '@')
    {
        return Err(invalid());
    }
    Ok(())
}

/// Strips surrounding quotes and backslash escapes from a display name.
fn unquote(raw: &str) -> String {
    let text = raw.trim();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        let inner = &text[1..text.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        text.to_string()
    }
}

/// Index of the first `<` outside quotes and comments.
fn angle_open(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_quoted(text, index),
            b'(' => index = skip_comment(text, index),
            b'<' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// Text of the first comment, e.g. `Name` in `a@b (Name)`.
fn first_comment(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_quoted(text, index),
            b'(' => {
                let end = skip_comment(text, index);
                let inner_end = if end > index && bytes.get(end - 1) == Some(&b')') {
                    end - 1
                } else {
                    end
                };
                return Some(text[index + 1..inner_end].to_string());
            }
            _ => index += 1,
        }
    }
    None
}

/// Removes every parenthesised comment (quoted strings are left alone).
fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let end = skip_quoted(text, index);
                out.push_str(&text[index..end]);
                index = end;
            }
            b'(' => index = skip_comment(text, index),
            _ => {
                let ch = text[index..].chars().next().unwrap_or(' ');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Content-Type, parameters, RFC 2231
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct MediaType {
    kind: String,
    subtype: String,
    params: BTreeMap<String, String>,
}

impl MediaType {
    fn text_plain() -> Self {
        Self {
            kind: "text".to_string(),
            subtype: "plain".to_string(),
            params: BTreeMap::new(),
        }
    }

    /// Charset parameter, defaulting to UTF-8 (the renderer's own default and
    /// what unlabelled 8-bit text almost always is).
    fn charset(&self) -> &str {
        self.params.get("charset").map_or("utf-8", String::as_str)
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    fn essence(&self) -> String {
        format!("{}/{}", self.kind, self.subtype)
    }
}

fn parse_media_type(raw: &str) -> Result<MediaType> {
    let (essence, params) = parse_parameterized(raw);
    let Some((kind, subtype)) = essence.split_once('/') else {
        return Err(Error::InvalidContentType(truncate(raw, 120)));
    };
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.bytes().all(is_tchar)
        || !subtype.bytes().all(is_tchar)
    {
        return Err(Error::InvalidContentType(truncate(raw, 120)));
    }
    Ok(MediaType {
        kind: kind.to_string(),
        subtype: subtype.to_string(),
        params,
    })
}

/// Parses `essence; key=value; key="quoted"` into a lowercased essence and a
/// parameter map, applying RFC 2231 continuations and extended values.
fn parse_parameterized(raw: &str) -> (String, BTreeMap<String, String>) {
    let bytes = raw.as_bytes();
    let mut essence_end = raw.len();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_quoted(raw, index),
            b'(' => index = skip_comment(raw, index),
            b';' => {
                essence_end = index;
                break;
            }
            _ => index += 1,
        }
    }
    let essence = strip_comments(&raw[..essence_end])
        .trim()
        .to_ascii_lowercase();

    let mut params: Vec<(String, String)> = Vec::new();
    let mut index = essence_end;
    while index < bytes.len() {
        index += 1; // skip ';'
        index = skip_ws_and_comments(raw, index);
        if index >= bytes.len() {
            break;
        }
        let name_start = index;
        while index < bytes.len() && is_tchar(bytes[index]) {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = raw[name_start..index].to_ascii_lowercase();
        let after_name = index;
        index = skip_ws_and_comments(raw, index);
        if bytes.get(index) != Some(&b'=') {
            index = after_name;
            continue;
        }
        index += 1;
        index = skip_ws_and_comments(raw, index);
        if bytes.get(index) == Some(&b'"') {
            let (value, next) = read_quoted(raw, index);
            params.push((name, value));
            index = next;
        } else {
            let value_start = index;
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            params.push((name, raw[value_start..index].trim().to_string()));
        }
    }

    (essence, assemble_params(params))
}

/// Applies RFC 2231: `name*0*=utf-8''…` continuations and `name*=` values.
fn assemble_params(raw: Vec<(String, String)>) -> BTreeMap<String, String> {
    let mut plain: BTreeMap<String, String> = BTreeMap::new();
    let mut extended: BTreeMap<String, Vec<(usize, bool, String)>> = BTreeMap::new();

    for (name, value) in raw {
        if let Some((base, rest)) = name.split_once('*') {
            let usable_base = !base.is_empty() && !base.contains('*');
            if usable_base && rest.is_empty() {
                // `name*=` — one extended segment.
                extended
                    .entry(base.to_string())
                    .or_default()
                    .push((0, true, value));
                continue;
            }
            let (number, is_extended) = match rest.strip_suffix('*') {
                Some(number) => (number, true),
                None => (rest, false),
            };
            if usable_base {
                if let Ok(position) = number.parse::<usize>() {
                    // `name*0=`, `name*0*=`, …
                    extended.entry(base.to_string()).or_default().push((
                        position,
                        is_extended,
                        value,
                    ));
                    continue;
                }
            }
        }
        plain.insert(name, value);
    }

    for (base, mut segments) in extended {
        segments.sort_by_key(|(position, _, _)| *position);
        let mut bytes = Vec::new();
        let mut declared = None;
        for (index, (_, is_extended, value)) in segments.into_iter().enumerate() {
            if is_extended {
                let payload = if index == 0 {
                    match value.split_once('\'') {
                        Some((charset_label, rest)) => {
                            declared = Some(charset_label.to_string());
                            rest.split_once('\'').map_or(rest, |(_, data)| data)
                        }
                        None => value.as_str(),
                    }
                } else {
                    value.as_str()
                };
                bytes.extend(percent_decode(payload));
            } else {
                bytes.extend_from_slice(value.as_bytes());
            }
        }
        let decoded = charset::decode(&bytes, declared.as_deref().unwrap_or("utf-8"));
        plain.insert(base, decoded);
    }

    plain
}

fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Transfer encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Identity,
    Base64,
    QuotedPrintable,
}

impl Encoding {
    fn parse(raw: Option<&str>) -> Result<Self> {
        let Some(raw) = raw else {
            return Ok(Self::Identity);
        };
        let cleaned = strip_comments(raw).trim().to_ascii_lowercase();
        match cleaned.as_str() {
            "" | "7bit" | "8bit" | "binary" => Ok(Self::Identity),
            "base64" => Ok(Self::Base64),
            "quoted-printable" => Ok(Self::QuotedPrintable),
            other => Err(Error::UnsupportedTransferEncoding(truncate(other, 60))),
        }
    }
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

/// Splits a multipart body into part slices (headers + body, delimiter removed).
fn split_multipart<'a>(body: &'a str, boundary: &str) -> Result<Vec<&'a str>> {
    let delimiter = format!("--{boundary}");
    let closing = format!("{delimiter}--");
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut offset = 0usize;
    let mut rest = body;
    let mut closed = false;

    loop {
        let (line, next) = next_line(rest);
        let line_end = offset + (rest.len() - next.len());
        let trimmed = line.trim_end_matches([' ', '\t']);

        if trimmed == delimiter || trimmed == closing {
            if let Some(start) = current.take() {
                parts.push(trim_ending(&body[start..offset]));
            }
            if trimmed == closing {
                closed = true;
                break;
            }
            current = Some(line_end);
        }

        offset = line_end;
        if next.is_empty() {
            break;
        }
        rest = next;
    }

    if !closed {
        return Err(Error::UnterminatedMultipart);
    }
    Ok(parts)
}

fn trim_ending(part: &str) -> &str {
    if let Some(rest) = part.strip_suffix("\r\n") {
        rest
    } else if let Some(rest) = part.strip_suffix('\n') {
        rest
    } else {
        part.strip_suffix('\r').unwrap_or(part)
    }
}

// ---------------------------------------------------------------------------
// Small scanning helpers
// ---------------------------------------------------------------------------

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Index just past a quoted string starting at `start` (which holds `"`).
fn skip_quoted(input: &str, start: usize) -> usize {
    let bytes = input.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// Index just past a comment starting at `start` (which holds `(`).
fn skip_comment(input: &str, start: usize) -> usize {
    let bytes = input.as_bytes();
    let mut depth = 0usize;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 1,
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    bytes.len()
}

/// Index just past an angle-addr starting at `start` (which holds `<`).
fn skip_angle(input: &str, start: usize) -> usize {
    let bytes = input.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_quoted(input, index),
            b'>' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn skip_ws_and_comments(input: &str, mut index: usize) -> usize {
    loop {
        while index < input.len() && input.as_bytes()[index].is_ascii_whitespace() {
            index += 1;
        }
        if input.as_bytes().get(index) == Some(&b'(') {
            index = skip_comment(input, index);
            continue;
        }
        return index;
    }
}

/// Reads a quoted string (starting at `start`) and returns its unescaped value
/// plus the index after the closing quote. Unterminated quotes are tolerated.
fn read_quoted(input: &str, start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut escaped = false;
    let mut end = input.len();
    for (offset, ch) in input[start..].char_indices() {
        if offset == 0 {
            continue; // opening quote
        }
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                end = start + offset + 1;
                break;
            }
            _ => out.push(ch),
        }
    }
    (out, end)
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut cut = max;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

/// Rejects filenames that would escape a download directory.
fn check_filename(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let drive_relative = bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic();
    let dangerous = name.is_empty()
        || name == "."
        || name == ".."
        || drive_relative
        || name
            .chars()
            .any(|ch| matches!(ch, '/' | '\\' | '\0') || ch.is_control());
    if dangerous {
        return Err(Error::UnsafeFilename(truncate(name, 120)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_line_handles_all_three_terminators() {
        assert_eq!(next_line("a\r\nb"), ("a", "b"));
        assert_eq!(next_line("a\nb"), ("a", "b"));
        assert_eq!(next_line("a\rb"), ("a", "b"));
        assert_eq!(next_line("a"), ("a", ""));
        assert_eq!(next_line(""), ("", ""));
    }

    #[test]
    fn header_block_unfolds_continuations() {
        let headers = parse_header_block("Subject: a\r\n\tb\r\nX: y", &Limits::default()).unwrap();
        assert_eq!(headers.get("subject"), Some("a b"));
        assert_eq!(headers.get("x"), Some("y"));
    }

    #[test]
    fn media_type_parameters_and_rfc2231() {
        let media = parse_media_type(
            "text/plain; charset=\"utf-8\"; filename*0*=utf-8''Gr%C3%BC; filename*1*=n.pdf",
        )
        .unwrap();
        assert_eq!(media.essence(), "text/plain");
        assert_eq!(media.charset(), "utf-8");
        assert_eq!(media.param("filename"), Some("Grün.pdf"));
    }

    #[test]
    fn split_multipart_ignores_preamble_and_epilogue() {
        let body = "preamble\r\n--b\r\nX: 1\r\n\r\nhello\r\n--b--\r\nepilogue";
        let parts = split_multipart(body, "b").unwrap();
        assert_eq!(parts, vec!["X: 1\r\n\r\nhello"]);
    }

    #[test]
    fn truncated_multipart_is_an_error() {
        assert_eq!(
            split_multipart("--b\r\n\r\nhello\r\n", "b"),
            Err(Error::UnterminatedMultipart)
        );
        assert_eq!(split_multipart("", "b"), Err(Error::UnterminatedMultipart));
    }

    #[test]
    fn address_scanner_respects_quotes_comments_and_groups() {
        let list = parse_address_list(
            "\"Doe, John\" <j@example.com>, a@example.com (Comment), Team: t1@example.com, t2@example.com;",
            "To",
        )
        .unwrap();
        assert_eq!(list.len(), 4);
        assert_eq!(list[0].name.as_deref(), Some("Doe, John"));
        assert_eq!(list[1].name.as_deref(), Some("Comment"));
        assert_eq!(list[2].address, "t1@example.com");
    }

    #[test]
    fn path_traversal_filenames_are_rejected() {
        for name in ["../etc/passwd", "..\\\\x", "C:pwn", "..", "a\0b"] {
            assert!(
                matches!(check_filename(name), Err(Error::UnsafeFilename(_))),
                "{name} must be rejected"
            );
        }
        assert!(check_filename("rechnung.pdf").is_ok());
    }

    #[test]
    fn truncate_never_splits_a_char() {
        assert_eq!(truncate("Grüße", 4), "Grü");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
