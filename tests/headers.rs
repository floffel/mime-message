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
    let raw = format!("From: a@example.com\r\nTo: b@example.com\r\n{block}\r\nhi");
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
        "To: b@example.com\r\n",
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
        "To: b@example.com\r\n",
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
    let raw = "From: a@example.com\r\nTo: b@example.com\r\nSubject: one\r\nSubject: two\r\n\r\nx";
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
    message
        .set_header(Header::new("x-a", "new").expect("header"))
        .expect("set");
    let names: Vec<&str> = message.headers().iter().map(Header::name).collect();
    assert_eq!(names, ["x-a", "X-B"]);
    assert_eq!(message.header("X-A"), Some("new"));

    // A new name is appended.
    message
        .set_header(Header::new("X-C", "c").expect("header"))
        .expect("set");
    assert_eq!(message.header("X-C"), Some("c"));
}

#[test]
fn push_and_remove_headers() {
    let mut message = parse("From: a@example.com\r\nX-A: 1\r\n\r\nx").expect("parse");
    message
        .push_header(Header::new("X-A", "2").expect("header"))
        .expect("push");
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
        .expect("header")
        .build()
        .expect("build");
    let rendered = raw_of(&message);
    assert!(rendered.contains("List-Unsubscribe: <mailto:u@example.com>\r\n"));
    assert_eq!(
        message.header("list-unsubscribe"),
        Some("<mailto:u@example.com>")
    );
}

#[test]
fn builder_rejects_modelled_header_names() {
    let error = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .header(Header::new("Subject", "spoofed").expect("header"))
        .expect_err("modelled header");
    assert_eq!(error, Error::DuplicateHeader("Subject".to_string()));
}

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

#[test]
fn modelled_header_names_are_rejected_at_the_mutation_site() {
    let mut message = parse("From: a@example.com\r\n\r\nx").expect("parse");
    assert_eq!(
        message
            .push_header(Header::new("Subject", "injected").expect("header"))
            .unwrap_err(),
        Error::DuplicateHeader("Subject".to_string())
    );
    assert_eq!(message.headers(), []);

    let subject = Header::new("subject", "injected").expect("header");
    assert_eq!(
        message.set_header(subject).unwrap_err(),
        Error::DuplicateHeader("subject".to_string())
    );
    assert_eq!(message.headers(), []);

    for name in ["From", "To", "content-type", "MIME-Version"] {
        let header = Header::new(name, "spoofed").expect("header");
        assert_eq!(
            header.name(),
            name,
            "the error must name the field as supplied"
        );
        assert_eq!(
            message.push_header(header).unwrap_err(),
            Error::DuplicateHeader(name.to_string())
        );
        assert_eq!(message.headers(), []);
    }

    message
        .push_header(Header::new("X-Trace", "ok").expect("header"))
        .expect("non-modelled headers still work");
    assert_eq!(message.header("X-Trace"), Some("ok"));
}

#[test]
fn header_values_with_line_breaks_are_rejected() {
    for (bad, byte) in [
        ("a\r\nBcc: evil@example.com", 0x0d),
        ("a\nb", 0x0a),
        ("a\rb", 0x0d),
        ("a\0b", 0x00),
        ("a\u{7f}b", 0x7f),
    ] {
        assert_eq!(
            Header::new("X-A", bad).unwrap_err(),
            Error::ControlCharacter {
                name: "X-A".to_string(),
                byte,
            },
            "{bad:?} must be rejected on byte 0x{byte:02x}"
        );
    }
    assert!(Header::new("X A", "x").is_err());
    assert!(Header::new("X:A", "x").is_err());
    assert!(Header::new("", "x").is_err());
}

#[test]
fn preserved_headers_reject_unicode_line_separators() {
    for (separator, byte) in [('\u{85}', 0xc2), ('\u{2028}', 0xe2), ('\u{2029}', 0xe2)] {
        let value = format!("one{separator}two");
        let error = Error::ControlCharacter {
            name: "X-A".to_string(),
            byte,
        };

        let raw = format!("From: a@example.com\r\nX-A: {value}\r\n\r\nx");
        assert_eq!(parse(&raw).unwrap_err(), error, "raw parse {separator:?}");

        let mut message = parse("From: a@example.com\r\n\r\nx").expect("parse");
        let header = Header::from_wire("X-A", format!(" {value}"))
            .expect_err("Header::from_wire rejects the separator itself");
        assert_eq!(header, error, "from_wire {separator:?}");

        let header = Header::new("X-A", value).expect("new header");
        assert_eq!(
            message.set_header(header).unwrap_err(),
            error,
            "set_header {separator:?}"
        );
        assert_eq!(message.headers(), []);
    }
}

#[test]
fn preserved_headers_keep_legal_folds() {
    let raw = "From: a@example.com\r\nTo: b@example.com\r\nX-A: one\r\n\ttwo\r\n\r\nx";
    let message = parse(raw).expect("parse");
    let rendered = raw_of(&message);
    assert!(rendered.contains("X-A: one\r\n\ttwo\r\n"));
    assert_eq!(message.header("X-A"), Some("one two"));
}

#[test]
fn from_wire_rejects_folds_that_end_the_header_block() {
    for bad in [" a\r\n ", " a\r\n\t", "\r\n b"] {
        assert_eq!(
            Header::from_wire("X-A", bad).unwrap_err(),
            Error::ControlCharacter {
                name: "X-A".to_string(),
                byte: 0x0d,
            },
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn render_parse_render_keeps_the_header_set() {
    let raw = concat!(
        "From: a@example.com\r\n",
        "To: b@example.com\r\n",
        "Subject: hi\r\n",
        "X-Folded: one\r\n",
        "\ttwo\r\n",
        "X-Other: value\r\n",
        "\r\n",
        "body",
    );
    let message = parse(raw).expect("parse");
    let once = parse(&raw_of(&message)).expect("parse once");
    let twice = parse(&raw_of(&once)).expect("parse twice");

    let names = |message: &Message| {
        message
            .headers()
            .iter()
            .map(|header| (header.name().to_string(), header.raw_value().to_string()))
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&twice), names(&message));
    assert_eq!(twice.subject, message.subject);
}

#[test]
fn parsed_header_names_are_validated_like_rendered_ones() {
    assert!(matches!(
        parse("From: a@example.com\r\nX A: 1\r\n\r\nx"),
        Err(Error::MalformedHeader { .. })
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
fn without_to_cc_and_bcc_the_builder_has_no_recipient() {
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
    let raw = "From: a@example.com\r\nTo: b@example.com\r\nX-Origin: München\r\n\r\nx";
    let message = parse(raw).expect("parse");
    let rendered = raw_of(&message);
    assert!(rendered.contains("X-Origin: München\r\n"));
    assert_eq!(
        parse(&rendered).expect("parse").headers(),
        message.headers()
    );
}
