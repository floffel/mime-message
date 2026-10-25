//! Header preservation: unknown fields survive a round-trip byte for byte, and
//! `Bcc` has a field of its own instead of being dropped.

use mime_message::{parse, Error, Header, Message};

fn raw_of(message: &Message) -> String {
    String::from_utf8(message.render().expect("render")).expect("utf-8")
}

// ---------------------------------------------------------------------------
// Preservation
// ---------------------------------------------------------------------------

#[test]
fn unknown_headers_keep_their_order_and_casing() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "X-First: 1\r\n",
        "reply-to: replies@example.com\r\n",
        "X-Last: 3\r\n",
        "\r\n",
        "hi",
    );
    let message = parse(raw).expect("parse");
    let names: Vec<&str> = message.headers().iter().map(Header::name).collect();
    assert_eq!(names, ["X-First", "reply-to", "X-Last"]);
    assert_eq!(message.header("REPLY-TO"), Some("replies@example.com"));
}

#[test]
fn unknown_headers_are_rerendered_byte_for_byte() {
    // Two spaces after the colon, a folded continuation, an empty value, an
    // 8-bit value and a colon inside a value all have to survive untouched.
    let block = concat!(
        "X-Spaced:   two  spaces\r\n",
        "X-Folded: one\r\n",
        "\ttwo\r\n",
        "X-Empty:\r\n",
        "X-8bit: Grüße\r\n",
        "X-Url: https://example.com:8443/path\r\n",
        "X-Trailing: value   \r\n",
    );
    let raw = format!("From: a@example.com\r\n{block}\r\nhi");
    let message = parse(&raw).expect("parse");
    let rendered = raw_of(&message);
    for line in block.split_inclusive("\r\n") {
        if line.starts_with("X-Folded") {
            continue;
        }
        assert!(
            rendered.contains(line),
            "field {line:?} was not reproduced in {rendered:?}"
        );
    }
    assert!(rendered.contains("X-Folded: one\r\n\ttwo\r\n"));
    // Parsed views agree with what a human reads.
    assert_eq!(message.header("X-Folded"), Some("one two"));
    assert_eq!(message.header("X-Empty"), Some(""));
    assert_eq!(message.header("X-8bit"), Some("Grüße"));
    assert_eq!(message.header("X-Trailing"), Some("value"));
}

#[test]
fn duplicate_unknown_headers_are_all_kept() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "X-Trace: one\r\n",
        "X-Other: x\r\n",
        "X-Trace: two\r\n",
        "\r\n",
        "hi",
    );
    let message = parse(raw).expect("parse");
    let traces: Vec<&str> = message
        .headers()
        .iter()
        .filter(|header| header.is("X-Trace"))
        .map(Header::value)
        .collect();
    assert_eq!(traces, ["one", "two"]);
    let rendered = raw_of(&message);
    let first = rendered.find("X-Trace: one").expect("first");
    let second = rendered.find("X-Trace: two").expect("second");
    assert!(first < second, "duplicates must keep their order");
}

#[test]
fn modelled_headers_are_not_preserved_a_second_time() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "Subject: hi\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "x",
    );
    let message = parse(raw).expect("parse");
    assert_eq!(message.headers().len(), 0);
    let rendered = raw_of(&message);
    assert_eq!(rendered.matches("Subject:").count(), 1);
    assert_eq!(rendered.matches("Content-Type:").count(), 1);
    assert_eq!(rendered.matches("MIME-Version:").count(), 1);
}

#[test]
fn a_duplicate_subject_is_not_resurrected_as_an_unknown_header() {
    let raw = "From: a@example.com\r\nSubject: one\r\nSubject: two\r\n\r\nx";
    let message = parse(raw).expect("parse");
    assert_eq!(message.subject, "one");
    assert_eq!(message.headers().len(), 0);
    assert_eq!(raw_of(&message).matches("Subject:").count(), 1);
}

#[test]
fn header_lookup_is_case_insensitive_and_first_wins() {
    let message = parse("From: a@example.com\r\nX-A: 1\r\nX-A: 2\r\n\r\nx").expect("parse");
    assert_eq!(message.header("x-a"), Some("1"));
    assert_eq!(message.header("X-A"), Some("1"));
    assert_eq!(message.header("X-Missing"), None);
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

#[test]
fn set_header_replaces_in_place_and_drops_duplicates() {
    let mut message =
        parse("From: a@example.com\r\nX-A: 1\r\nX-B: b\r\nX-A: 2\r\n\r\nx").expect("parse");
    message.set_header(Header::new("x-a", "new").expect("header"));
    let names: Vec<&str> = message.headers().iter().map(Header::name).collect();
    assert_eq!(names, ["x-a", "X-B"]);
    assert_eq!(message.header("X-A"), Some("new"));

    // A new name is appended.
    message.set_header(Header::new("X-C", "c").expect("header"));
    assert_eq!(message.header("X-C"), Some("c"));
}

#[test]
fn push_and_remove_headers() {
    let mut message = parse("From: a@example.com\r\nX-A: 1\r\n\r\nx").expect("parse");
    message.push_header(Header::new("X-A", "2").expect("header"));
    assert_eq!(message.headers().len(), 2);
    let removed = message.remove_header("X-A").expect("removed");
    assert_eq!(removed.value(), "1");
    assert_eq!(message.header("X-A"), Some("2"));
    assert!(message.remove_header("X-Missing").is_none());
}

#[test]
fn builder_headers_are_rendered() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .header(Header::new("List-Unsubscribe", "<mailto:u@example.com>").expect("header"))
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(rendered.contains("List-Unsubscribe: <mailto:u@example.com>\r\n"));
    assert_eq!(
        message.header("list-unsubscribe"),
        Some("<mailto:u@example.com>")
    );
}

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

#[test]
fn a_preserved_header_cannot_smuggle_a_modelled_one() {
    let mut message = parse("From: a@example.com\r\n\r\nx").expect("parse");
    message.push_header(Header::new("Subject", "injected").expect("header"));
    assert_eq!(
        message.render().unwrap_err(),
        Error::DuplicateHeader("Subject".to_string())
    );
    message.push_header(Header::new("content-type", "text/html").expect("header"));
    let _ = message.remove_header("Subject");
    assert!(matches!(message.render(), Err(Error::DuplicateHeader(_))));
}

#[test]
fn header_values_with_line_breaks_are_rejected() {
    for bad in [
        "a\r\nBcc: evil@example.com",
        "a\nb",
        "a\rb",
        "a\0b",
        "a\u{7f}b",
    ] {
        assert!(
            matches!(Header::new("X-A", bad), Err(Error::ControlCharacter(_))),
            "{bad:?} must be rejected"
        );
    }
    assert!(Header::new("X A", "x").is_err());
    assert!(Header::new("X:A", "x").is_err());
    assert!(Header::new("", "x").is_err());
}

#[test]
fn parsed_header_names_are_validated_like_rendered_ones() {
    assert!(matches!(
        parse("From: a@example.com\r\nX A: 1\r\n\r\nx"),
        Err(Error::MalformedHeader(_))
    ));
}

// ---------------------------------------------------------------------------
// Bcc
// ---------------------------------------------------------------------------

#[test]
fn bcc_is_parsed_into_its_own_field() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "To: b@example.com\r\n",
        "Bcc: \"Secret\" <secret@example.com>, other@example.com\r\n",
        "\r\n",
        "hi",
    );
    let message = parse(raw).expect("parse");
    assert_eq!(message.bcc.len(), 2);
    assert_eq!(message.bcc[0].name.as_deref(), Some("Secret"));
    assert_eq!(message.bcc[1].address, "other@example.com");
    // A parsed Bcc is never re-rendered and never preserved as a raw header.
    let rendered = raw_of(&message);
    assert!(!rendered.contains("Bcc"));
    assert!(!rendered.contains("secret@example.com"));
}

#[test]
fn a_bcc_only_message_renders_without_a_to_header() {
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .bcc("b@example.com")
        .expect("bcc")
        .body("hi")
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(!rendered.contains("To:"));
    assert!(rendered.contains("From: a@example.com\r\n"));
    let parsed = parse(&rendered).expect("round trip");
    assert_eq!(parsed.to.len(), 0);
    assert_eq!(parsed.bcc.len(), 0);
}

#[test]
fn duplicate_bcc_headers_are_joined_like_to() {
    let raw = "From: a@example.com\r\nBcc: one@example.com\r\nBcc: two@example.com\r\n\r\nx";
    let message = parse(raw).expect("parse");
    assert_eq!(message.bcc.len(), 2);
}

#[test]
fn without_to_and_bcc_the_builder_has_no_recipient() {
    assert_eq!(
        Message::builder()
            .from("a@example.com")
            .expect("from")
            .build()
            .unwrap_err(),
        Error::NoRecipients
    );
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn render_parse_render_is_stable_with_preserved_headers() {
    let raw = concat!(
        "From: \"Shop\" <shop@example.com>\r\n",
        "To: kunde@example.com\r\n",
        "Subject: Grüße\r\n",
        "X-Spaced:   keep\r\n",
        "Authentication-Results: mx.example.com; dkim=pass\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "body\r\n",
    );
    let once = raw_of(&parse(raw).expect("parse"));
    let twice = raw_of(&parse(&once).expect("parse"));
    assert_eq!(once, twice);
    assert!(once.contains("X-Spaced:   keep\r\n"));
    assert!(once.contains("Authentication-Results: mx.example.com; dkim=pass\r\n"));
}

#[test]
fn preserved_headers_from_an_8bit_message_survive() {
    let raw = "From: a@example.com\r\nX-Origin: München\r\n\r\nx";
    let message = parse(raw).expect("parse");
    let rendered = raw_of(&message);
    assert!(rendered.contains("X-Origin: München\r\n"));
    assert_eq!(
        parse(&rendered).expect("parse").headers(),
        message.headers()
    );
}
