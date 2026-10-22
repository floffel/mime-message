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
    let to = message
        .to
        .iter()
        .map(render_mailbox)
        .collect::<Vec<_>>()
        .join(", ");
    push_header(&mut out, "To", &to, true)?;
    push_header(&mut out, "Subject", &encode_word(&message.subject), true)?;
    if let Some(date) = &message.date {
        push_header(&mut out, "Date", date, false)?;
    }
    if let Some(id) = &message.message_id {
        push_header(&mut out, "Message-ID", id, false)?;
    }
    push_header(&mut out, "MIME-Version", "1.0", false)?;

    if message.attachments.is_empty() {
        push_header(&mut out, "Content-Type", "text/plain; charset=utf-8", false)?;
        push_header(&mut out, "Content-Transfer-Encoding", "8bit", false)?;
        out.push_str(CRLF);
        out.push_str(&normalise_newlines(&message.body));
    } else {
        let boundary = boundary_for(message);
        push_header(
            &mut out,
            "Content-Type",
            &format!("multipart/mixed; boundary=\"{boundary}\""),
            false,
        )?;
        out.push_str(CRLF);

        out.push_str(&format!("--{boundary}{CRLF}"));
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        out.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
        out.push_str(&normalise_newlines(&message.body));
        out.push_str(CRLF);

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
    }

    Ok(out.into_bytes())
}

fn render_mailbox(mailbox: &Mailbox) -> String {
    match &mailbox.name {
        Some(name) if name.is_ascii() && !name.contains('"') => {
            format!("\"{name}\" <{}>", mailbox.address)
        }
        Some(name) => format!("{} <{}>", encode_word(name), mailbox.address),
        None => mailbox.address.clone(),
    }
}

/// Appends `Name: value` with folding and CRLF injection protection.
fn push_header(out: &mut String, name: &'static str, value: &str, _foldable: bool) -> Result<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(Error::HeaderInjection(name));
    }
    let folded = fold_header(name, value);
    out.push_str(&folded);
    out.push_str(CRLF);
    Ok(())
}

/// Folds at spaces so no line exceeds 78 characters (RFC 5322 §2.1.1).
fn fold_header(name: &str, value: &str) -> String {
    let mut line = format!("{name}: ");
    let mut result = String::new();
    for word in value.split(' ') {
        if line.len() + word.len() + 1 > MAX_LINE && line.len() > name.len() + 2 {
            result.push_str(line.trim_end());
            result.push_str(CRLF);
            line = String::from(" ");
        }
        line.push_str(word);
        line.push(' ');
    }
    result.push_str(line.trim_end());
    result
}

/// RFC 2047 encoded-word for non-ASCII header content.
fn encode_word(value: &str) -> String {
    const MAX_BYTES: usize = 30;
    if value.is_ascii() {
        return value.to_string();
    }
    // RFC 2047: each encoded-word must decode on its own, so split at char
    // boundaries with a byte budget that is a multiple of 3 (base64 pads
    // otherwise) and keeps the word well under 75 characters.

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

fn sanitise_filename(name: &str) -> String {
    name.replace(['\r', '\n', '"'], "_")
}

/// Deterministic boundary derived from the content — stable across runs.
fn boundary_for(message: &Message) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    message.subject.hash(&mut hasher);
    message.body.hash(&mut hasher);
    for attachment in &message.attachments {
        attachment.filename.hash(&mut hasher);
        attachment.data.hash(&mut hasher);
    }
    format!("=_mime_message_{:016x}", hasher.finish())
}
