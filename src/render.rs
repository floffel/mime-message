// Formatting into a plain String is clearer than threading write!/Result
// through every helper; String writes cannot fail.
#![allow(clippy::format_push_string)]

//! Rendering: headers, folding, encoding, multipart bodies.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::{check_recipients, cid, ensure_not_modelled, is_tchar, Mailbox, Message};

const CRLF: &str = "\r\n";
const MAX_LINE: usize = 78;
const MAX_ASCII_FALLBACK: usize = 60;
const RFC2231_CHUNK: usize = 48;

/// Longest body line RFC 5322 §2.1.1 permits, CRLF excluded.
const MAX_BODY_LINE: usize = 998;

/// Renders `message` into RFC 5322 bytes.
pub(crate) fn render(message: &Message) -> Result<Vec<u8>> {
    check_recipients(message)?;
    let mut out = String::new();

    push_header(&mut out, "From", &render_mailbox(&message.from)?, true)?;
    if !message.to.is_empty() {
        push_header(&mut out, "To", &render_mailboxes(&message.to)?, true)?;
    }
    if !message.cc.is_empty() {
        push_header(&mut out, "Cc", &render_mailboxes(&message.cc)?, true)?;
    }
    push_header(&mut out, "Subject", &encode_word(&message.subject), true)?;
    if let Some(date) = &message.date {
        push_header(&mut out, "Date", date, false)?;
    }
    if let Some(id) = &message.message_id {
        push_header(&mut out, "Message-ID", id, false)?;
    }
    // `Bcc` is deliberately not rendered: it is what makes it blind.
    push_preserved(&mut out, message)?;
    push_header(&mut out, "MIME-Version", "1.0", false)?;

    let has_html = message.html_body.is_some();
    if !has_html && message.attachments.is_empty() {
        push_header(&mut out, "Content-Type", "text/plain; charset=utf-8", false)?;
        let (encoding, body) = encode_text_body(&message.body);
        push_header(&mut out, "Content-Transfer-Encoding", encoding, false)?;
        out.push_str(CRLF);
        out.push_str(&body);
        return Ok(out.into_bytes());
    }

    // `multipart/related` is the container inline parts belong in (RFC 2387):
    // it is only used when the HTML body has something to point at.
    let all_inline = !message.attachments.is_empty()
        && message
            .attachments
            .iter()
            .all(|attachment| attachment.content_id.is_some());
    let related = has_html && all_inline;
    let kind = if related {
        "related"
    } else if message.attachments.is_empty() {
        "alternative"
    } else {
        "mixed"
    };
    let (boundary, inner_boundary) =
        choose_boundaries(message, has_html && !message.attachments.is_empty())?;
    push_header(
        &mut out,
        "Content-Type",
        &format!("multipart/{kind}; boundary=\"{boundary}\""),
        false,
    )?;
    out.push_str(CRLF);

    if let Some(html) = message.html_body.as_ref() {
        if message.attachments.is_empty() {
            write_text_section(&mut out, &boundary, "text/plain", &message.body)?;
            write_text_section(&mut out, &boundary, "text/html", html)?;
        } else {
            // mixed(alternative(plain, html), attachments) or
            // related(alternative(plain, html), inline parts)
            let inner = inner_boundary
                .as_deref()
                .expect("nested alternative boundary was chosen above");
            write_part_header(
                &mut out,
                &boundary,
                &[(
                    "Content-Type",
                    format!("multipart/alternative; boundary=\"{inner}\""),
                )],
            )?;
            write_text_section(&mut out, inner, "text/plain", &message.body)?;
            write_text_section(&mut out, inner, "text/html", html)?;
            out.push_str(&format!("--{inner}--{CRLF}"));
        }
    } else {
        write_text_section(&mut out, &boundary, "text/plain", &message.body)?;
    }

    for attachment in &message.attachments {
        write_attachment(&mut out, &boundary, attachment)?;
    }
    out.push_str(&format!("--{boundary}--{CRLF}"));

    Ok(out.into_bytes())
}

/// Writes the header fields the crate does not model, byte for byte.
fn push_preserved(out: &mut String, message: &Message) -> Result<()> {
    for header in message.headers() {
        if !header.name().bytes().all(is_tchar) {
            return Err(Error::malformed_name(header.name()));
        }
        // Rendering `From` twice is header injection with extra steps; the
        // mutation APIs reject this earlier, and the renderer keeps the guard.
        ensure_not_modelled(header)?;
        check_preserved_header(header.raw_value(), header.name())?;
        out.push_str(header.name());
        out.push(':');
        out.push_str(header.raw_value());
        out.push_str(CRLF);
    }
    Ok(())
}

/// Rejects preserved headers that cannot be emitted inside RFC limits.
fn check_preserved_header(value: &str, name: &str) -> Result<()> {
    crate::header::check_rendered_header(name, value)
}

fn write_part_header(
    out: &mut String,
    boundary: &str,
    headers: &[(&'static str, String)],
) -> Result<()> {
    out.push_str(&format!("--{boundary}{CRLF}"));
    for (name, value) in headers {
        push_part_header(out, name, value)?;
    }
    out.push_str(CRLF);
    Ok(())
}

/// Writes one header line of a MIME part, folded like a top-level header.
///
/// A part header *is* a header: `Content-Type: multipart/alternative;
/// boundary="…"` is 83 bytes unfolded, past the 78 a reader may rely on
/// (RFC 5322 §2.1.1), so the folding rules are the same inside a part as at
/// the top of the message.
fn push_part_header(out: &mut String, name: &'static str, value: &str) -> Result<()> {
    if has_forbidden_chars(value) {
        return Err(Error::HeaderInjection(name));
    }
    let folded = fold_header(name, value)?;
    out.push_str(&folded);
    out.push_str(CRLF);
    Ok(())
}

fn write_text_section(
    out: &mut String,
    boundary: &str,
    content_type: &str,
    text: &str,
) -> Result<()> {
    let (encoding, body) = encode_text_body(text);
    write_part_header(
        out,
        boundary,
        &[
            ("Content-Type", format!("{content_type}; charset=utf-8")),
            ("Content-Transfer-Encoding", encoding.to_string()),
        ],
    )?;
    out.push_str(&body);
    out.push_str(CRLF);
    Ok(())
}

/// Picks the `Content-Transfer-Encoding` for a text body and returns it encoded.
///
/// `8bit` is only safe for a next hop that speaks 8BITMIME (RFC 6152) or
/// SMTPUTF8 (RFC 6532), and RFC 5322 §2.1.1 forbids a line above 998 octets
/// outright. Both cases go out as quoted-printable, which is 7-bit clean and
/// wraps at 76 characters; everything else keeps the original bytes verbatim.
fn encode_text_body(text: &str) -> (&'static str, String) {
    let normalised = normalise_newlines(text);
    if normalised.is_ascii() && !has_overlong_line(&normalised) {
        ("8bit", normalised)
    } else {
        (
            "quoted-printable",
            crate::transfer::encode_quoted_printable(&normalised),
        )
    }
}

/// `true` when any line exceeds the 998 octets RFC 5322 §2.1.1 allows.
fn has_overlong_line(text: &str) -> bool {
    text.split(CRLF).any(|line| line.len() > MAX_BODY_LINE)
}

fn write_attachment(
    out: &mut String,
    boundary: &str,
    attachment: &crate::Attachment,
) -> Result<()> {
    let content_id = attachment
        .content_id
        .as_deref()
        .map(cid::checked_content_id)
        .transpose()?;
    let disposition = if content_id.is_some() {
        "inline"
    } else {
        "attachment"
    };

    let mut headers: Vec<(&'static str, String)> = vec![
        ("Content-Type", attachment.content_type.clone()),
        ("Content-Transfer-Encoding", "base64".to_string()),
    ];
    if let Some(id) = &content_id {
        headers.push(("Content-ID", format!("<{id}>")));
    }
    headers.push((
        "Content-Disposition",
        render_content_disposition(disposition, &attachment.filename),
    ));
    write_part_header(out, boundary, &headers)?;

    out.push_str(&base64_wrapped(&attachment.data));
    out.push_str(CRLF);
    Ok(())
}

fn render_mailboxes(mailboxes: &[Mailbox]) -> Result<String> {
    let mut rendered = Vec::with_capacity(mailboxes.len());
    for mailbox in mailboxes {
        rendered.push(render_mailbox(mailbox)?);
    }
    Ok(rendered.join(", "))
}

fn render_mailbox(mailbox: &Mailbox) -> Result<String> {
    crate::parse::validate_address(&mailbox.address)?;
    Ok(match &mailbox.name {
        Some(name) if name.is_ascii() => {
            format!("\"{}\" <{}>", escape_quoted(name), mailbox.address)
        }
        Some(name) => format!("{} <{}>", encode_word(name), mailbox.address),
        None => mailbox.address.clone(),
    })
}

/// Renders `Content-Disposition`, RFC 2231-encoding a non-ASCII filename.
fn render_content_disposition(disposition: &str, filename: &str) -> String {
    let filename = sanitise_filename(filename);
    if filename.is_ascii() {
        return format!("{disposition}; filename=\"{filename}\"");
    }

    let fallback = ascii_filename_fallback(&filename);
    let encoded = percent_encode_rfc2231(&filename);
    let chunks = split_rfc2231(&encoded);
    let mut rendered = format!("{disposition}; filename=\"{fallback}\"");
    for (index, chunk) in chunks.iter().enumerate() {
        if index == 0 {
            rendered.push_str(&format!("; filename*0*=UTF-8''{chunk}"));
        } else {
            rendered.push_str(&format!("; filename*{index}*={chunk}"));
        }
    }
    rendered
}

/// A plain fallback for receivers that do not understand RFC 2231.
fn ascii_filename_fallback(name: &str) -> String {
    name.chars()
        .take(MAX_ASCII_FALLBACK)
        .map(|ch| if ch.is_ascii() { ch } else { '_' })
        .collect()
}

/// RFC 2231 §3.2 `attr-char` is the set that may stay undecorated.
fn percent_encode_rfc2231(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if is_rfc2231_attr_char(byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn is_rfc2231_attr_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// Splits an encoded value into RFC 2231 continuation chunks.
///
/// Each chunk is kept below the folded-continuation budget, and splits only
/// between encoded pieces so `%XX` escapes stay intact.
fn split_rfc2231(encoded: &str) -> Vec<&str> {
    let bytes = encoded.as_bytes();
    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let mut end = start;
        while end < bytes.len() {
            let piece_len = if bytes[end] == b'%' && end + 2 < bytes.len() {
                3
            } else {
                1
            };
            if end > start && end - start + piece_len > RFC2231_CHUNK {
                break;
            }
            end += piece_len;
        }
        chunks.push(&encoded[start..end]);
        start = end;
    }
    chunks
}

/// Escapes a display name for a quoted-string: only `\` and `"` are special.
fn escape_quoted(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Appends `Name: value` with folding and CRLF injection protection.
fn push_header(out: &mut String, name: &'static str, value: &str, _foldable: bool) -> Result<()> {
    if has_forbidden_chars(value) {
        return Err(Error::HeaderInjection(name));
    }
    let folded = fold_header(name, value)?;
    out.push_str(&folded);
    out.push_str(CRLF);
    Ok(())
}

/// Rejects every character that could start a new header line.
fn has_forbidden_chars(value: &str) -> bool {
    crate::header::has_forbidden_chars(value)
}

/// Folds at single-space boundaries so no line exceeds 78 characters
/// (RFC 5322 §2.1.1).
///
/// Folding replaces one space with CRLF + space; since unfolding removes only
/// the CRLF, the value round-trips byte for byte. Runs of whitespace are never
/// used as a fold point, so they survive unchanged. A single token longer than
/// the budget cannot be folded without changing the value, so it is rejected
/// rather than emitted on an over-long line.
fn fold_header(name: &str, value: &str) -> Result<String> {
    let tokens: Vec<&str> = value.split(' ').collect();
    let mut out = format!("{name}: ");
    let mut line_len = header_len(name) + 2;

    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            let previous = tokens[index - 1];
            let foldable =
                !token.is_empty() && !previous.is_empty() && line_len > header_len(name) + 2;
            if foldable && line_len + 1 + header_len(token) > MAX_LINE {
                out.push_str(CRLF);
                out.push(' ');
                line_len = 1;
            } else {
                out.push(' ');
                line_len += 1;
            }
        }
        out.push_str(token);
        line_len += header_len(token);
        if line_len > MAX_LINE {
            return Err(Error::LimitExceeded {
                what: "header line length",
                limit: MAX_LINE,
            });
        }
    }
    Ok(out)
}

/// Header folding measures characters, not UTF-8 bytes.
fn header_len(text: &str) -> usize {
    text.chars().count()
}

/// RFC 2047 encoded-word for non-ASCII header content.
fn encode_word(value: &str) -> String {
    const MAX_BYTES: usize = 30;
    if value.is_ascii() {
        return value.to_string();
    }
    // RFC 2047: each encoded-word must decode on its own, so split at char
    // boundaries with a byte budget that keeps the word well under 75
    // characters.

    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if current.len() + ch.len_utf8() > MAX_BYTES {
            words.push(STANDARD.encode(current.as_bytes()));
            current.clear();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(STANDARD.encode(current.as_bytes()));
    }
    words
        .into_iter()
        .map(|w| format!("=?UTF-8?B?{w}?="))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalise_newlines(body: &str) -> String {
    body.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', CRLF)
}

fn base64_wrapped(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    let mut out = String::new();
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push_str(CRLF);
    }
    out
}

/// Neutralises anything that could break out of the quoted filename.
fn sanitise_filename(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if matches!(ch, '\r' | '\n' | '"' | '\\') || ch.is_control() {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

/// The largest number of boundary candidates tried before giving up.
const MAX_BOUNDARY_ATTEMPTS: usize = 1024;

/// Picks multipart boundary strings that do not occur as delimiter lines in any
/// encoded part.
fn choose_boundaries(
    message: &Message,
    nested_alternative: bool,
) -> Result<(String, Option<String>)> {
    choose_boundaries_with(
        nested_alternative,
        |attempt| boundary_for(message, attempt),
        |candidate| boundary_conflicts(message, candidate),
    )
}

fn choose_boundaries_with(
    nested_alternative: bool,
    mut candidate_at: impl FnMut(usize) -> String,
    mut conflicts: impl FnMut(&str) -> bool,
) -> Result<(String, Option<String>)> {
    for attempt in 0..MAX_BOUNDARY_ATTEMPTS {
        let boundary = candidate_at(attempt);
        let inner = nested_alternative.then(|| format!("{boundary}_alt"));
        let boundary_ok = !conflicts(&boundary);
        let inner_ok = inner.as_deref().is_none_or(|inner| !conflicts(inner));
        if boundary_ok && inner_ok {
            return Ok((boundary, inner));
        }
    }
    Err(Error::LimitExceeded {
        what: "multipart boundary attempts",
        limit: MAX_BOUNDARY_ATTEMPTS,
    })
}

/// A deterministic multipart boundary derived from the content and the attempt
/// number.
///
/// SHA-256 is a documented stable digest, so a stored draft that is re-rendered
/// by a later build gets the same boundary. The collision loop, not the digest
/// itself, keeps the boundary safe for the payload.
fn boundary_for(message: &Message, attempt: usize) -> String {
    let mut hasher = Sha256::new();
    hash_text(&mut hasher, &message.subject);
    hash_text(&mut hasher, &message.body);
    hash_optional_text(&mut hasher, message.html_body.as_deref());
    for mailbox in &message.cc {
        hash_text(&mut hasher, &mailbox.address);
    }
    for header in message.headers() {
        hash_text(&mut hasher, header.name());
        hash_text(&mut hasher, header.raw_value());
    }
    for attachment in &message.attachments {
        hash_text(&mut hasher, &attachment.filename);
        hash_optional_text(&mut hasher, attachment.content_id.as_deref());
        hash_bytes(&mut hasher, &attachment.data);
    }
    hasher.update(u64::try_from(attempt).unwrap_or(u64::MAX).to_be_bytes());
    let digest = hasher.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    format!("=_mime_message_{:016x}", u64::from_be_bytes(head))
}

fn hash_text(hasher: &mut Sha256, text: &str) {
    hash_bytes(hasher, text.as_bytes());
}

fn hash_optional_text(hasher: &mut Sha256, text: Option<&str>) {
    match text {
        Some(text) => {
            hasher.update([1]);
            hash_text(hasher, text);
        }
        None => hasher.update([0]),
    }
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

/// `true` when an encoded part contains a line that a receiver would split on.
fn boundary_conflicts(message: &Message, boundary: &str) -> bool {
    let delimiter = format!("--{boundary}");
    let closing = format!("{delimiter}--");

    let text_conflicts = |text: &str| {
        let (_, encoded) = encode_text_body(text);
        has_delimiter_line(&encoded, &delimiter, &closing)
    };
    if text_conflicts(&message.body) {
        return true;
    }
    if message.html_body.as_deref().is_some_and(text_conflicts) {
        return true;
    }
    message.attachments.iter().any(|attachment| {
        let encoded = base64_wrapped(&attachment.data);
        has_delimiter_line(&encoded, &delimiter, &closing)
            || has_delimiter_line(&attachment.filename, &delimiter, &closing)
            || attachment
                .content_id
                .as_deref()
                .is_some_and(|id| has_delimiter_line(id, &delimiter, &closing))
    })
}

fn has_delimiter_line(text: &str, delimiter: &str, closing: &str) -> bool {
    text.split('\n').any(|raw_line| {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim_end_matches([' ', '\t']);
        trimmed == delimiter || trimmed == closing
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Header;

    #[test]
    fn render_still_rejects_a_modelled_preserved_header() {
        let mut message =
            Message::parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
        let header = Header::new("Subject", "spoofed").expect("header");
        // Bypass the mutation API: this is the renderer's own guard.
        message.headers.push(header);
        assert_eq!(
            message.render().unwrap_err(),
            Error::DuplicateHeader("Subject".to_string())
        );
    }

    #[test]
    fn boundary_collision_detection_sees_a_body_line() {
        let mut message =
            Message::parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
        message.body = "before\n--=_mime_message_0123456789abcdef\nafter".to_string();

        assert!(boundary_conflicts(
            &message,
            "=_mime_message_0123456789abcdef"
        ));
        assert!(!boundary_conflicts(&message, "not-the-boundary"));
    }

    #[test]
    fn boundary_collision_detection_sees_an_attachment_line() {
        let mut message =
            Message::parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
        message.attachments.push(crate::Attachment::new(
            "note\n--=_mime_message_0123456789abcdef\n.txt",
            "text/plain",
            Vec::new(),
        ));

        assert!(boundary_conflicts(
            &message,
            "=_mime_message_0123456789abcdef"
        ));
    }

    #[test]
    fn boundary_choice_skips_a_conflicting_candidate() {
        let (boundary, inner) = choose_boundaries_with(
            true,
            |attempt| format!("candidate-{attempt}"),
            |candidate| candidate == "candidate-0",
        )
        .expect("second candidate is safe");

        assert_eq!(boundary, "candidate-1");
        assert_eq!(inner.as_deref(), Some("candidate-1_alt"));
    }

    #[test]
    fn boundary_choice_skips_body_and_filename_candidate() {
        let mut message =
            Message::parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
        let candidate = boundary_for(&message, 0);
        message.body = format!("before\n--{candidate}\nafter");
        message.attachments.push(crate::Attachment::new(
            format!("note\n--{candidate}\n.txt"),
            "text/plain",
            Vec::new(),
        ));

        assert!(boundary_conflicts(&message, &candidate));
        let (chosen, _) = choose_boundaries(&message, false).expect("a safe boundary");
        assert_ne!(chosen, candidate);
        assert!(!boundary_conflicts(&message, &chosen));
    }

    #[test]
    fn boundary_choice_errors_when_no_candidate_is_safe() {
        assert_eq!(
            choose_boundaries_with(false, |attempt| format!("candidate-{attempt}"), |_| true),
            Err(Error::LimitExceeded {
                what: "multipart boundary attempts",
                limit: MAX_BOUNDARY_ATTEMPTS,
            })
        );
    }

    #[test]
    fn boundary_seed_is_deterministic_and_attempt_sensitive() {
        let message =
            Message::parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
        let first = boundary_for(&message, 0);
        assert_eq!(first, boundary_for(&message, 0));
        assert_ne!(first, boundary_for(&message, 1));
    }
}
