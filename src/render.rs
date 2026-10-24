// Formatting into a plain String is clearer than threading write!/Result
// through every helper; String writes cannot fail.
#![allow(clippy::format_push_string)]

//! Rendering: headers, folding, encoding, multipart bodies.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{Error, Result};
use crate::{Mailbox, Message};

const CRLF: &str = "\r\n";
const MAX_LINE: usize = 78;

/// Renders `message` into RFC 5322 bytes.
pub(crate) fn render(message: &Message) -> Result<Vec<u8>> {
    let mut out = String::new();

    push_header(&mut out, "From", &render_mailbox(&message.from), true)?;
    push_header(&mut out, "To", &render_mailboxes(&message.to), true)?;
    if !message.cc.is_empty() {
        push_header(&mut out, "Cc", &render_mailboxes(&message.cc), true)?;
    }
    push_header(&mut out, "Subject", &encode_word(&message.subject), true)?;
    if let Some(date) = &message.date {
        push_header(&mut out, "Date", date, false)?;
    }
    if let Some(id) = &message.message_id {
        push_header(&mut out, "Message-ID", id, false)?;
    }
    push_header(&mut out, "MIME-Version", "1.0", false)?;

    let has_html = message.html_body.is_some();
    if !has_html && message.attachments.is_empty() {
        push_header(&mut out, "Content-Type", "text/plain; charset=utf-8", false)?;
        push_header(&mut out, "Content-Transfer-Encoding", "8bit", false)?;
        out.push_str(CRLF);
        out.push_str(&normalise_newlines(&message.body));
        return Ok(out.into_bytes());
    }

    let boundary = boundary_for(message);
    let kind = if message.attachments.is_empty() {
        "alternative"
    } else {
        "mixed"
    };
    push_header(
        &mut out,
        "Content-Type",
        &format!("multipart/{kind}; boundary=\"{boundary}\""),
        false,
    )?;
    out.push_str(CRLF);

    match (&message.html_body, message.attachments.is_empty()) {
        (Some(html), true) => {
            write_text_section(&mut out, &boundary, "text/plain", &message.body);
            write_text_section(&mut out, &boundary, "text/html", html);
        }
        (Some(html), false) => {
            // mixed(alternative(plain, html), attachments)
            let inner = format!("{boundary}_alt");
            out.push_str(&format!("--{boundary}{CRLF}"));
            out.push_str(&format!(
                "Content-Type: multipart/alternative; boundary=\"{inner}\"{CRLF}{CRLF}"
            ));
            write_text_section(&mut out, &inner, "text/plain", &message.body);
            write_text_section(&mut out, &inner, "text/html", html);
            out.push_str(&format!("--{inner}--{CRLF}"));
        }
        (None, _) => write_text_section(&mut out, &boundary, "text/plain", &message.body),
    }

    for attachment in &message.attachments {
        out.push_str(&format!("--{boundary}{CRLF}"));
        if attachment.content_type.contains('\r') || attachment.content_type.contains('\n') {
            return Err(Error::HeaderInjection("Content-Type"));
        }
        out.push_str(&format!("Content-Type: {}\r\n", attachment.content_type));
        out.push_str("Content-Transfer-Encoding: base64\r\n");
        out.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n\r\n",
            sanitise_filename(&attachment.filename)
        ));
        out.push_str(&base64_wrapped(&attachment.data));
        out.push_str(CRLF);
    }
    out.push_str(&format!("--{boundary}--{CRLF}"));

    Ok(out.into_bytes())
}

fn write_text_section(out: &mut String, boundary: &str, content_type: &str, text: &str) {
    out.push_str(&format!("--{boundary}{CRLF}"));
    out.push_str(&format!(
        "Content-Type: {content_type}; charset=utf-8{CRLF}"
    ));
    out.push_str(&format!("Content-Transfer-Encoding: 8bit{CRLF}{CRLF}"));
    out.push_str(&normalise_newlines(text));
    out.push_str(CRLF);
}

fn render_mailboxes(mailboxes: &[Mailbox]) -> String {
    mailboxes
        .iter()
        .map(render_mailbox)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_mailbox(mailbox: &Mailbox) -> String {
    match &mailbox.name {
        Some(name) if name.is_ascii() => {
            format!("\"{}\" <{}>", escape_quoted(name), mailbox.address)
        }
        Some(name) => format!("{} <{}>", encode_word(name), mailbox.address),
        None => mailbox.address.clone(),
    }
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
    let folded = fold_header(name, value);
    out.push_str(&folded);
    out.push_str(CRLF);
    Ok(())
}

/// Rejects every character that could start a new header line.
fn has_forbidden_chars(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(ch, '\r' | '\n' | '\0' | '\u{85}' | '\u{2028}' | '\u{2029}')
            || (ch.is_control() && ch != '\t')
    })
}

/// Folds at single-space boundaries so no line exceeds 78 characters
/// (RFC 5322 §2.1.1).
///
/// Folding replaces one space with CRLF + space; since unfolding removes only
/// the CRLF, the value round-trips byte for byte. Runs of whitespace are never
/// used as a fold point, so they survive unchanged.
fn fold_header(name: &str, value: &str) -> String {
    let tokens: Vec<&str> = value.split(' ').collect();
    let mut out = format!("{name}: ");
    let mut line_len = name.len() + 2;

    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            let previous = tokens[index - 1];
            let foldable = !token.is_empty() && !previous.is_empty() && line_len > name.len() + 2;
            if foldable && line_len + 1 + token.len() > MAX_LINE {
                out.push_str(CRLF);
                out.push(' ');
                line_len = 1;
            } else {
                out.push(' ');
                line_len += 1;
            }
        }
        out.push_str(token);
        line_len += token.len();
    }
    out
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

/// Deterministic boundary derived from the content — stable across runs.
fn boundary_for(message: &Message) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    message.subject.hash(&mut hasher);
    message.body.hash(&mut hasher);
    message.html_body.hash(&mut hasher);
    for mailbox in &message.cc {
        mailbox.address.hash(&mut hasher);
    }
    for attachment in &message.attachments {
        attachment.filename.hash(&mut hasher);
        attachment.data.hash(&mut hasher);
    }
    format!("=_mime_message_{:016x}", hasher.finish())
}
