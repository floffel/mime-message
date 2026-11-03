//! What a `ControlCharacter` rejection has to say: which field, and which byte.
//!
//! The variant used to carry the field name and nothing else, so an operator
//! holding the error could not tell a NUL from a VT from a DEL, and no test could
//! assert which byte the check objected to. Each test below pins one half of the
//! payload against the input it came from, including the bytes on both sides of
//! the rule (tab versus VT, `0x1f` versus SP, `0x7e` versus DEL).

use mime_message::{Attachment, Error, Header, Message};

/// The byte a rejection reports, or `None` when the value is accepted.
fn byte_of(name: &str, value: &str) -> Option<u8> {
    match Header::new(name, value) {
        Err(Error::ControlCharacter { byte, .. }) => Some(byte),
        Err(other) => panic!("expected a control-byte rejection, got {other:?}"),
        Ok(header) => {
            assert_eq!(header.value(), value);
            None
        }
    }
}

#[test]
fn every_forbidden_byte_is_reported_as_itself() {
    // The three line ends are the security-relevant ones; the rest are the
    // control bytes a broken mailer emits. None of them may collapse into one
    // another in the payload.
    let cases = [
        (0x00u8, "NUL"),
        (0x08, "BS"),
        (0x0a, "LF"),
        (0x0b, "VT"),
        (0x0c, "FF"),
        (0x0d, "CR"),
        (0x1f, "US"),
        (0x7f, "DEL"),
    ];
    for (byte, label) in cases {
        let value =
            String::from_utf8(vec![b'a', byte, b'b']).expect("ASCII control bytes are UTF-8");
        assert_eq!(
            byte_of("X-A", &value),
            Some(byte),
            "{label} (0x{byte:02x}) must be reported as itself"
        );
    }
}

#[test]
fn the_boundary_pair_of_the_control_byte_rule() {
    // Everything below SP is forbidden except tab, and DEL is forbidden: the
    // value on each side of both edges is what proves the edge is where the
    // documentation says it is.
    assert_eq!(
        byte_of("X-A", "a\u{1f}b"),
        Some(0x1f),
        "0x1f is just outside"
    );
    assert_eq!(byte_of("X-A", "a b"), None, "SP is just inside");
    assert_eq!(
        byte_of("X-A", "a\tb"),
        None,
        "tab is the one allowed control"
    );
    assert_eq!(byte_of("X-A", "a\u{0b}b"), Some(0x0b), "VT is one past tab");
    assert_eq!(byte_of("X-A", "a\u{7e}b"), None, "0x7e is just inside");
    assert_eq!(
        byte_of("X-A", "a\u{7f}b"),
        Some(0x7f),
        "DEL is just outside"
    );
    // Eight-bit text is not a control byte: a value may carry raw UTF-8.
    assert_eq!(byte_of("X-Gruss", "Müller"), None);
}

#[test]
fn the_name_is_the_field_and_the_byte_is_the_one_in_its_value() {
    // `Subject: a\0b` is rejected while reading a message. The field is
    // `Subject`, and the value's own bytes are nowhere in the name — which is
    // exactly the confusion the old payload invited.
    let raw = "From: a@example.com\r\nSubject: a\u{0}b\r\n\r\nx";
    assert_eq!(
        mime_message::parse(raw).unwrap_err(),
        Error::ControlCharacter {
            name: "Subject".to_string(),
            byte: 0x00,
        }
    );

    let raw = "From: a@example.com\r\nX-Note: ok\u{0b}\r\n\r\nx";
    assert_eq!(
        mime_message::parse(raw).unwrap_err(),
        Error::ControlCharacter {
            name: "X-Note".to_string(),
            byte: 0x0b,
        }
    );

    // The same field name, a valid value: the rule is about the byte, not the
    // name.
    assert!(mime_message::parse("From: a@example.com\r\nX-Note: ok\r\n\r\nx").is_ok());
}

#[test]
fn a_cr_that_is_not_a_fold_reports_its_cr() {
    // A fold is CRLF followed by whitespace. Anything else is a CR that has no
    // business being in the value, however the byte after it looks, so 0x0d is
    // what the payload holds.
    for broken in [" a\r\nb", " a\rb", " a\r\n"] {
        assert_eq!(
            Header::from_wire("X-A", broken).unwrap_err(),
            Error::ControlCharacter {
                name: "X-A".to_string(),
                byte: 0x0d,
            },
            "{broken:?} must blame the CR"
        );
    }
    // And the legal fold one byte further in still parses.
    assert_eq!(
        Header::from_wire("X-A", " a\r\n b")
            .expect("a fold is legal")
            .value(),
        "a b"
    );
}

#[test]
fn the_renderer_names_the_field_it_rejected() {
    // The `Content-ID` check reads characters rather than bytes, and it is the
    // only control-byte check a caller can reach with a broken value: the field
    // and its byte still have to come back.
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .attachment(Attachment::new("a.png", "image/png", vec![1]).with_content_id("a"))
        .build()
        .expect("build");

    let render_with = |content_id: &str| {
        let mut broken = message.clone();
        broken.attachments[0].content_id = Some(content_id.to_string());
        broken.render().unwrap_err()
    };

    for (content_id, byte) in [
        ("a\r\nBcc: evil@example.com", 0x0d),
        ("a\u{0}b", 0x00),
        ("a b", 0x20),
        // A character, not a byte: U+0085 (NEL) starts with 0xc2 in UTF-8, so
        // that is the byte that identifies it.
        ("a\u{85}b", 0xc2),
    ] {
        assert_eq!(
            render_with(content_id),
            Error::ControlCharacter {
                name: "Content-ID".to_string(),
                byte,
            },
            "{content_id:?} must report 0x{byte:02x}"
        );
    }

    // The value on the inside of the rule renders.
    let mut fine = message;
    fine.attachments[0].content_id = Some("a@example.com".to_string());
    assert!(fine.render().is_ok());
}

#[test]
fn the_rendered_error_names_the_field_and_the_byte() {
    // A log line has to say the same thing the payload does, in hex, so an
    // operator can tell the bytes apart without a debugger.
    let raw = "From: a@example.com\r\nSubject: a\u{0b}b\r\n\r\nx";
    assert_eq!(
        mime_message::parse(raw).unwrap_err().to_string(),
        r#"value of header "Subject" contains control byte 0x0b"#
    );
}
