//! Rendering rules: structure, folding, encoding, injection safety.

use mime_message::{Attachment, Error, Message};

fn simple() -> Message {
    Message::builder()
        .from("Shop <shop@example.com>")
        .unwrap()
        .to("kunde@example.com")
        .unwrap()
        .subject("Ihre Rechnung")
        .body("Anbei die Rechnung.")
        .date("Tue, 21 Oct 2026 10:00:00 +0000")
        .build()
        .unwrap()
}

#[test]
fn simple_message_has_headers_and_crlf_body() {
    let raw = simple().render().unwrap();
    let text = String::from_utf8(raw).unwrap();

    assert!(text.starts_with("From: \"Shop\" <shop@example.com>\r\n"));
    assert!(text.contains("To: kunde@example.com\r\n"));
    assert!(text.contains("Subject: Ihre Rechnung\r\n"));
    assert!(text.contains("MIME-Version: 1.0\r\n"));
    assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    assert!(text.contains("\r\n\r\nAnbei die Rechnung."));
    // No bare LF anywhere.
    assert!(!text.replace("\r\n", "").contains('\n'));
}

#[test]
fn body_newlines_are_normalised_to_crlf() {
    let msg = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.com")
        .unwrap()
        .subject("x")
        .body("eins\nzwei\n\ndrei")
        .build()
        .unwrap();
    let text = String::from_utf8(msg.render().unwrap()).unwrap();
    assert!(text.contains("eins\r\nzwei\r\n\r\ndrei"));
    assert!(!text.replace("\r\n", "").contains('\n'));
}

#[test]
fn non_ascii_subject_is_rfc2047_encoded() {
    let msg = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.com")
        .unwrap()
        .subject("Grüße aus München")
        .body("hi")
        .build()
        .unwrap();
    let text = String::from_utf8(msg.render().unwrap()).unwrap();
    assert!(text.contains("=?UTF-8?B?"), "subject not encoded: {text}");
    assert!(!text.contains("München"));
}

#[test]
fn header_injection_is_rejected() {
    let msg = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.com")
        .unwrap()
        .subject("Hi\r\nBcc: attacker@example.com")
        .body("x")
        .build()
        .unwrap();
    assert_eq!(msg.render().unwrap_err(), Error::HeaderInjection("Subject"));
}

#[test]
fn malformed_mailboxes_are_rejected() {
    assert!(matches!(
        Message::builder().from("no-at-sign"),
        Err(Error::InvalidMailbox(_))
    ));
    assert!(matches!(
        Message::builder().to(""),
        Err(Error::EmptyHeader(_))
    ));
}

#[test]
fn message_without_recipient_is_rejected() {
    let err = Message::builder()
        .from("a@example.com")
        .unwrap()
        .subject("x")
        .body("y")
        .build()
        .unwrap_err();
    assert_eq!(err, Error::NoRecipients);
}

#[test]
fn attachment_switches_to_multipart_with_base64() {
    let msg = simple().clone_with_attachment(Attachment::new(
        "rechnung.pdf",
        "application/pdf",
        b"%PDF-1.4 test".to_vec(),
    ));
    let text = String::from_utf8(msg.render().unwrap()).unwrap();

    assert!(text.contains("Content-Type: multipart/mixed; boundary=\""));
    assert!(text.contains("Content-Disposition: attachment; filename=\"rechnung.pdf\""));
    assert!(text.contains("Content-Transfer-Encoding: base64"));
    assert!(text.trim_end().ends_with("--"));
}

#[test]
fn attachment_filename_cannot_inject_headers() {
    let msg = simple().clone_with_attachment(Attachment::new(
        "evil\"\r\nX-Injected: 1",
        "text/plain",
        b"x".to_vec(),
    ));
    let text = String::from_utf8(msg.render().unwrap()).unwrap();
    // The name is neutralised in place: no CR/LF may survive, so X-Injected can
    // never become a header line of its own.
    assert!(!text.contains("\r\nX-Injected"));
    assert!(text.contains("evil___X-Injected: 1"));
}

#[test]
fn long_headers_are_folded_below_78_characters() {
    let msg = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.com")
        .unwrap()
        .subject("wort ".repeat(40).trim())
        .body("x")
        .build()
        .unwrap();
    let text = String::from_utf8(msg.render().unwrap()).unwrap();
    for line in text.split("\r\n") {
        assert!(line.len() <= 78, "line too long: {line:?}");
    }
}

trait CloneWithAttachment {
    fn clone_with_attachment(&self, attachment: Attachment) -> Message;
}

impl CloneWithAttachment for Message {
    fn clone_with_attachment(&self, attachment: Attachment) -> Message {
        let mut copy = self.clone();
        copy.attachments.push(attachment);
        copy
    }
}
