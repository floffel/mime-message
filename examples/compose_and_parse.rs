//! Compose a typical invoice mail — plain text, HTML alternative, an inline
//! logo and a PDF attachment — then parse the rendered bytes back.
//!
//! ```text
//! cargo run --example compose_and_parse
//! ```
//!
//! The point is the round trip: what `render()` writes, `parse()` reads back,
//! and the guarantees the README states are checked here instead of described.

use mime_message::{Attachment, Message};

/// Smallest thing that is still a PNG header; the crate never interprets it.
const LOGO: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A fixed `Date:` and `Message-ID:` keep the output byte-for-byte stable:
    // the crate never reads the clock, so neither does this example.
    let message = Message::builder()
        .from("Shop <shop@example.com>")?
        .to("Kunde <kunde@example.com>")?
        .subject("Ihre Rechnung für Oktober – Grüße aus München")
        .date("Thu, 29 Oct 2026 09:00:00 +0100")
        .message_id("<rechnung-2026-10@example.com>")
        .body("Anbei die Rechnung für Oktober.\n")
        .html_body(
            "<p>Anbei die Rechnung für Oktober.</p>\
             <p><img src=\"cid:logo@example.com\" alt=\"Logo\"></p>",
        )
        .attachment(
            Attachment::new("logo.png", "image/png", LOGO.to_vec())
                .with_content_id("logo@example.com"),
        )
        .attachment(Attachment::new(
            "rechnung.pdf",
            "application/pdf",
            b"%PDF-1.4\n% placeholder, the crate does not read it\n".to_vec(),
        ))
        .build()?;

    let raw = message.render()?;
    let text = std::str::from_utf8(&raw)
        .map_err(|error| format!("rendered message is not valid UTF-8: {error}"))?;

    // Guarantee 1: CRLF everywhere, never a bare LF, so no MIME part can be
    // split by a line ending the wire does not allow.
    if text.replace("\r\n", "").contains('\n') {
        return Err("rendered message contains a bare LF".into());
    }
    // Guarantee 2: no header line is longer than 78 bytes (RFC 5322 §2.1.1),
    // the headers of the multipart parts included. Lines in the bodies are the
    // caller's business — HTML and long paragraphs are legitimately wide.
    let header_block = text.split("\r\n\r\n").next().unwrap_or_default();
    for line in header_block.split("\r\n") {
        if line.len() > 78 {
            return Err(format!("header line of {} bytes exceeds 78: {line:?}", line.len()).into());
        }
    }

    println!("--- rendered headers ---\n{header_block}");
    println!("--- {} bytes total ---", raw.len());

    let parsed = Message::parse(text)?;

    // Guarantee 3: the round trip loses nothing the crate claims to model.
    // Bodies are normalised to CRLF while rendering (a bare LF is invalid
    // inside a MIME part), so the round trip preserves the text, not the
    // caller's line endings.
    assert_eq!(
        parsed.subject, message.subject,
        "subject survived the round trip"
    );
    assert_eq!(
        parsed.body.replace("\r\n", "\n"),
        message.body,
        "text body survived the round trip"
    );
    assert_eq!(
        parsed.html_body, message.html_body,
        "HTML alternative survived the round trip"
    );
    assert_eq!(
        parsed.attachments.len(),
        2,
        "inline logo plus PDF attachment"
    );

    let logo = parsed
        .part_by_content_id("cid:<logo@example.com>")
        .ok_or("the inline logo part did not come back")?;
    assert_eq!(logo.data, LOGO, "attachment bytes are unchanged");

    // Guarantee 4: `cid:` references resolve locally — nothing is fetched.
    let html = parsed.html_body.as_deref().ok_or("HTML body is missing")?;
    let inlined = parsed.rewrite_cid_references(html);
    assert!(
        inlined.contains("src=\"data:image/png;base64,"),
        "the cid: reference was rewritten to a data URI"
    );

    println!(
        "round trip ok: subject, both bodies, {} attachments",
        parsed.attachments.len()
    );
    for attachment in &parsed.attachments {
        println!(
            "  {} ({}), {} bytes, content-id: {}",
            attachment.filename,
            attachment.content_type,
            attachment.data.len(),
            attachment.content_id.as_deref().unwrap_or("-")
        );
    }

    Ok(())
}
