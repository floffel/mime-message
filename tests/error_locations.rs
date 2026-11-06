//! Where a structural parse failure happened: which entity, which line, which
//! byte.
//!
//! A parser for untrusted wire data has to answer that from its own error type,
//! not from a log line: this file pins the payload of `MalformedHeader`,
//! `InvalidContentType` and `InvalidBase64` — the numbering, the boundary
//! between "inside the payload" and "just past it", and the two `0`s that mean
//! "this call had no wire position at all".

use mime_message::{parse, Error, Header};

/// A multipart mail whose parts carry no `From:`, so each failure below is about
/// the part and never about the envelope.
const MULTIPART: &str = concat!(
    "From: a@example.com\r\n",
    "Content-Type: multipart/mixed; boundary=b\r\n",
    "\r\n",
    "--b\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "one\r\n",
    "--b\r\n",
);

#[test]
fn malformed_header_reports_the_part_and_the_line() {
    // The top-level entity is part 1, the first child of `multipart` part 2, and
    // this broken child part 3: `X A` is its second header line.
    let raw =
        format!("{MULTIPART}Content-Transfer-Encoding: base64\r\nX A: 1\r\n\r\nQUJD\r\n--b--\r\n");
    assert_eq!(
        parse(&raw).unwrap_err(),
        Error::MalformedHeader {
            part: 3,
            line: 2,
            text: "X A: 1".to_string(),
        }
    );
}

#[test]
fn the_reported_line_is_the_one_that_fails_not_the_block() {
    // The last line of a block is the block's own boundary: line 3 of 3 fails.
    let last = "From: a@example.com\r\nSubject: ok\r\nX A: 1\r\n\r\nx";
    assert_eq!(
        parse(last).unwrap_err(),
        Error::MalformedHeader {
            part: 1,
            line: 3,
            text: "X A: 1".to_string(),
        }
    );
    // The first line is line 1, not 0.
    let first = "X A: 1\r\nSubject: ok\r\n\r\nx";
    assert_eq!(
        parse(first).unwrap_err(),
        Error::MalformedHeader {
            part: 1,
            line: 1,
            text: "X A: 1".to_string(),
        }
    );
    // One line further inside the block: the same field name is fine.
    assert!(parse("From: a@example.com\r\nSubject: ok\r\nX-A: 1\r\n\r\nx").is_ok());
}

#[test]
fn a_continuation_line_without_a_field_names_its_line() {
    // A fold on line 1 has nothing to attach to.
    assert_eq!(
        parse("\tindented continuation without header\r\n\r\nx").unwrap_err(),
        Error::MalformedHeader {
            part: 1,
            line: 1,
            text: "\tindented continuation without header".to_string(),
        }
    );
    // The same tab inside a block continues the field above it, so it parses.
    assert!(parse("From: a@example.com\r\nSubject: ok\r\n\tmore subject\r\n\r\nx").is_ok());
}

#[test]
fn malformed_header_text_stays_truncated() {
    // The cap is 120 bytes: the line at the limit is kept whole, one byte more is
    // cut — the payload of an error is a hint, not a copy of the message.
    let at_the_limit = "X".repeat(115) + " A: 1";
    let over = "X".repeat(116) + " A: 1";
    assert_eq!(at_the_limit.len(), 120);
    assert_eq!(over.len(), 121);

    let text_of = |line: &str| match parse(&format!("From: a@example.com\r\n{line}\r\n\r\nx")) {
        Err(Error::MalformedHeader { text, .. }) => text,
        other => panic!("expected a malformed header, got {other:?}"),
    };
    assert_eq!(text_of(&at_the_limit), at_the_limit);
    assert_eq!(text_of(&over), &over[..120]);
}

#[test]
fn invalid_content_type_names_the_part() {
    // The top-level entity is part 1; a bad media type in the second child is
    // part 3, and the value is the one that was rejected.
    let raw = format!("{MULTIPART}Content-Type: text\r\n\r\nx\r\n--b--\r\n");
    assert_eq!(
        parse(&raw).unwrap_err(),
        Error::InvalidContentType {
            part: 3,
            text: "text".to_string(),
        }
    );
}

#[test]
fn invalid_base64_names_the_part_and_the_byte() {
    // `SGVs\r\nbG8*` folds a payload whose '*' sits at byte 9 of the part body:
    // the offset counts the line break the decoder skipped, because that is the
    // offset a caller can look up in the message they have.
    let raw = format!(
        "{MULTIPART}Content-Type: application/octet-stream\r\n\
         Content-Transfer-Encoding: base64\r\n\r\nSGVs\r\nbG8*\r\n--b--\r\n"
    );
    let Error::InvalidBase64 { part, offset, .. } = parse(&raw).unwrap_err() else {
        panic!("expected InvalidBase64");
    };
    assert_eq!((part, offset), (3, 9));
}

#[test]
fn invalid_base64_points_past_the_end_when_no_byte_is_wrong() {
    // One symbol is not a quad: there is no offending byte, so the location is
    // the body length, the position just past the payload.
    let raw = format!("{MULTIPART}Content-Transfer-Encoding: base64\r\n\r\nS\r\n--b--\r\n");
    let Error::InvalidBase64 { part, offset, .. } = parse(&raw).unwrap_err() else {
        panic!("expected InvalidBase64");
    };
    assert_eq!((part, offset), (3, 1));

    // And the same body with a complete quad of the right length parses: the
    // boundary is the payload length, not a quirk of the sample.
    let ok = format!("{MULTIPART}Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--b--\r\n");
    assert_eq!(parse(&ok).unwrap().attachments[0].data, b"ABC");
}

#[test]
fn the_body_of_the_message_itself_is_part_one() {
    let raw = "From: a@example.com\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJ*\r\n";
    let Error::InvalidBase64 { part, offset, .. } = parse(raw).unwrap_err() else {
        panic!("expected InvalidBase64");
    };
    assert_eq!((part, offset), (1, 3));
}

#[test]
fn a_field_without_a_message_has_no_position() {
    // `Header::new` sees a name, not a header block: 0 means "unknown", the way a
    // compiler diagnostic without a span says line 0.
    assert_eq!(
        Header::new("X A", "1").unwrap_err(),
        Error::MalformedHeader {
            part: 0,
            line: 0,
            text: "X A".to_string(),
        }
    );
    assert_eq!(
        Header::from_wire("", "1").unwrap_err(),
        Error::MalformedHeader {
            part: 0,
            line: 0,
            text: String::new(),
        }
    );
}

#[test]
fn the_rendered_error_carries_the_location() {
    let bad_header = "From: a@example.com\r\nX A: 1\r\n\r\nx";
    assert_eq!(
        parse(bad_header).unwrap_err().to_string(),
        r#"malformed header at part 1, line 2: "X A: 1""#
    );

    let bad_base64 = "From: a@example.com\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJ*\r\n";
    assert_eq!(
        parse(bad_base64).unwrap_err().to_string(),
        "invalid base64 payload (part 1, offset 3)"
    );

    let bad_type = "From: a@example.com\r\nContent-Type: text\r\n\r\nx";
    assert_eq!(
        parse(bad_type).unwrap_err().to_string(),
        r#"invalid Content-Type (part 1): "text""#
    );
}
