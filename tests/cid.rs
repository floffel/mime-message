//! Inline parts: `Content-ID` survives parsing, `cid:` references resolve
//! without network access, and the renderer emits `multipart/related` when the
//! message really is one.

use mime_message::{cid, parse, Attachment, Error, Message};

fn raw_of(message: &Message) -> String {
    String::from_utf8(message.render().expect("render")).expect("utf-8")
}

fn related_message() -> &'static str {
    concat!(
        "From: a@example.com\r\n",
        "To: b@example.com\r\n",
        "Subject: inline\r\n",
        "Content-Type: multipart/related; boundary=\"rel\"\r\n",
        "\r\n",
        "--rel\r\n",
        "Content-Type: multipart/alternative; boundary=\"alt\"\r\n",
        "\r\n",
        "--alt\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Grüße\r\n",
        "--alt\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>Grüße <img src=\"cid:logo@example.com\"></p>\r\n",
        "--alt--\r\n",
        "--rel\r\n",
        "Content-Type: image/png\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "Content-ID: <logo@example.com>\r\n",
        "Content-Disposition: inline\r\n",
        "\r\n",
        "iVBORw0KGgo=\r\n",
        "--rel--\r\n",
    )
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn content_id_is_kept_per_part() {
    let message = parse(related_message()).expect("parse");
    assert_eq!(
        message.html_body.as_deref(),
        Some("<p>Grüße <img src=\"cid:logo@example.com\"></p>")
    );
    assert_eq!(message.inline_parts().count(), 1);
    let part = message
        .part_by_content_id("logo@example.com")
        .expect("inline part");
    assert_eq!(part.content_type, "image/png");
    assert_eq!(part.content_id.as_deref(), Some("logo@example.com"));
    assert_eq!(part.data, b"\x89PNG\r\n\x1a\n");
    // A part without Content-ID is a normal attachment.
    assert_eq!(message.attachments.len(), 1);
}

#[test]
fn content_id_lookups_accept_the_html_spelling() {
    let message = parse(related_message()).expect("parse");
    for spelling in [
        "logo@example.com",
        "cid:logo@example.com",
        "cid:<logo@example.com>",
        " <logo@example.com> ",
        "CID:logo@example.com",
    ] {
        assert!(
            message.part_by_content_id(spelling).is_some(),
            "{spelling:?} must resolve"
        );
    }
    assert!(message.part_by_content_id("other").is_none());
}

#[test]
fn content_ids_are_case_sensitive() {
    let message = parse(related_message()).expect("parse");
    assert!(message.part_by_content_id("LOGO@example.com").is_none());
}

#[test]
fn unusual_content_ids_are_preserved() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "Content-Type: multipart/mixed; boundary=b\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: image/gif\r\n",
        "Content-ID: <a.b+c_d-e@sub.example>\r\n",
        "\r\n",
        "x\r\n",
        "--b\r\n",
        "Content-Type: image/gif\r\n",
        "Content-ID: <12345>\r\n",
        "\r\n",
        "y\r\n",
        "--b--\r\n",
    );
    let message = parse(raw).expect("parse");
    assert_eq!(message.attachments.len(), 2);
    assert_eq!(
        message.attachments[0].content_id.as_deref(),
        Some("a.b+c_d-e@sub.example")
    );
    assert_eq!(message.attachments[1].content_id.as_deref(), Some("12345"));
    assert!(message.part_by_content_id("12345").is_some());
}

#[test]
fn an_empty_content_id_is_not_recorded() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "Content-Type: multipart/mixed; boundary=b\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: image/gif\r\n",
        "Content-ID: <>\r\n",
        "\r\n",
        "x\r\n",
        "--b--\r\n",
    );
    let message = parse(raw).expect("parse");
    assert!(message.attachments[0].content_id.is_none());
}

// ---------------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------------

#[test]
fn cid_references_become_data_uris() {
    let message = parse(related_message()).expect("parse");
    let rewritten = message.rewrite_cid_references(&message.html_body.clone().expect("html"));
    assert!(
        rewritten.contains("src=\"data:image/png;base64,iVBORw0KGgo=\""),
        "{rewritten}"
    );
    assert!(!rewritten.contains("cid:"));
}

#[test]
fn unresolved_references_are_left_alone() {
    let message = parse(related_message()).expect("parse");
    let html = "<img src=\"cid:missing\"><p>cid: also in text</p>";
    assert_eq!(message.rewrite_cid_references(html), html);
}

#[test]
fn a_custom_resolver_can_point_at_urls() {
    let message = parse(related_message()).expect("parse");
    let html = message.html_body.clone().expect("html");
    let rewritten = cid::rewrite(&html, |reference| {
        message
            .part_by_content_id(reference)
            .map(|_| format!("/attachments/{reference}"))
    });
    assert_eq!(
        rewritten,
        "<p>Grüße <img src=\"/attachments/logo@example.com\"></p>"
    );
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

#[test]
fn inline_parts_render_as_multipart_related() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .subject("inline")
        .body("Grüße")
        .html_body("<p>Grüße <img src=\"cid:logo\"></p>")
        .attachment(
            Attachment::new("logo.png", "image/png", b"\x89PNG".to_vec())
                .with_content_id("<logo@example.com>"),
        )
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(rendered.contains("Content-Type: multipart/related; boundary="));
    assert!(rendered.contains("Content-ID: <logo@example.com>\r\n"));
    assert!(rendered.contains("Content-Disposition: inline; filename=\"logo.png\""));

    let parsed = parse(&rendered).expect("reparse");
    assert_eq!(
        parsed
            .part_by_content_id("cid:logo@example.com")
            .map(|part| part.data.clone()),
        Some(b"\x89PNG".to_vec())
    );
}

#[test]
fn a_mixed_message_with_inline_and_plain_parts_stays_mixed() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .html_body("<img src=\"cid:logo\">")
        .attachment(Attachment::new("logo.png", "image/png", vec![1]).with_content_id("logo"))
        .attachment(Attachment::new("report.pdf", "application/pdf", vec![2]))
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(rendered.contains("Content-Type: multipart/mixed; boundary="));
    assert!(rendered.contains("Content-ID: <logo>\r\n"));
    assert!(rendered.contains("Content-Disposition: attachment; filename=\"report.pdf\""));
    let parsed = parse(&rendered).expect("reparse");
    assert_eq!(parsed.inline_parts().count(), 1);
}

#[test]
fn a_message_without_html_never_becomes_related() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .attachment(Attachment::new("logo.png", "image/png", vec![1]).with_content_id("logo"))
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(rendered.contains("Content-Type: multipart/mixed; boundary="));
}

#[test]
fn a_content_id_cannot_inject_a_header() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .attachment(Attachment::new("a.png", "image/png", vec![1]).with_content_id("a"))
        .build()
        .expect("build");
    let mut broken = message.clone();
    broken.attachments[0].content_id = Some("a\r\nBcc: evil@example.com".to_string());
    assert!(matches!(broken.render(), Err(Error::ControlCharacter(_))));

    let mut empty = message.clone();
    empty.attachments[0].content_id = Some("<>".to_string());
    assert_eq!(
        empty.render().unwrap_err(),
        Error::EmptyHeader("Content-ID")
    );
}

#[test]
fn rendering_inline_parts_is_deterministic() {
    let build = || {
        Message::builder()
            .from("a@example.com")
            .expect("from")
            .to("b@example.com")
            .expect("to")
            .body("hi")
            .html_body("<img src=\"cid:logo\">")
            .attachment(Attachment::new("logo.png", "image/png", vec![9]).with_content_id("logo"))
            .build()
            .expect("build")
    };
    assert_eq!(build().render(), build().render());
}

#[test]
fn cid_helpers_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Attachment>();
    let message = parse(related_message()).expect("parse");
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let message = message.clone();
            std::thread::spawn(move || message.part_by_content_id("logo@example.com").is_some())
        })
        .collect();
    for thread in threads {
        assert!(thread.join().expect("join"));
    }
}
