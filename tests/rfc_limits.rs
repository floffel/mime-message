//! The numeric rules of RFC 5322, RFC 2045 and RFC 2047, one test per rule: a
//! limit is only a limit when the value just inside it and the value just
//! outside it are both pinned.

use mime_message::transfer;
use mime_message::{Attachment, Message};
use proptest::prelude::*;

/// RFC 5322 §2.1.1: a line SHOULD be at most 78 characters.
const MAX_LINE_SHOULD: usize = 78;
/// RFC 5322 §2.1.1: a line MUST be at most 998 characters.
const MAX_LINE_MUST: usize = 998;
/// RFC 2047 §2: an encoded-word MUST be at most 75 characters.
const MAX_ENCODED_WORD: usize = 75;
/// RFC 2045 §6.7: a quoted-printable line MUST be at most 76 characters.
const MAX_QUOTED_PRINTABLE_LINE: usize = 76;

fn build(subject: &str, body: &str) -> Vec<u8> {
    Message::builder()
        .from("Shop <shop@example.com>")
        .expect("from")
        .to("kunde@example.com")
        .expect("to")
        .subject(subject)
        .body(body)
        .build()
        .expect("build")
        .render()
        .expect("render")
}

/// The body between the first empty line and the end.
fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").expect("header/body separator").1
}

/// One header value, unfolded: a fold is CRLF + space.
fn value_of(raw: &str, name: &str) -> String {
    let headers = raw.split("\r\n\r\n").next().expect("headers");
    let mut value: Option<String> = None;
    for line in headers.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(current) = value.as_mut() {
                current.push(' ');
                current.push_str(line.trim_start());
            }
            continue;
        }
        if let Some((field, rest)) = line.split_once(':') {
            if field.eq_ignore_ascii_case(name) {
                value = Some(rest.trim_start().to_string());
            }
        }
    }
    value.unwrap_or_else(|| panic!("no {name} header"))
}

#[test]
fn header_lines_stay_within_78_octets() {
    let raw = build(&"wort ".repeat(80), "text");
    let text = String::from_utf8(raw).expect("ascii");
    for line in text.split("\r\n") {
        assert!(
            line.len() <= MAX_LINE_SHOULD,
            "line of {} chars: {:?}",
            line.len(),
            line
        );
    }
}

#[test]
fn each_encoded_word_decodes_on_its_own_and_is_within_75_chars() {
    let subject = "ü".repeat(120);
    let text = String::from_utf8(build(&subject, "text")).expect("ascii");
    let value = value_of(&text, "Subject");
    let mut rebuilt = String::new();
    let mut words = 0usize;
    for word in value.split(' ').filter(|word| !word.is_empty()) {
        assert!(
            word.len() <= MAX_ENCODED_WORD,
            "encoded-word of {} chars: {:?}",
            word.len(),
            word
        );
        assert!(
            word.starts_with("=?UTF-8?B?"),
            "not an encoded-word: {word:?}"
        );
        rebuilt.push_str(&mime_message::rfc2047::decode(word));
        words += 1;
    }
    assert!(words > 1, "a 120-character subject cannot be one word");
    assert_eq!(rebuilt, subject);
}

#[test]
fn body_lines_never_exceed_the_998_octet_must() {
    let body = "a".repeat(2000);
    let raw = build("s", &body);
    let text = String::from_utf8(raw.clone()).expect("ascii");
    assert_eq!(
        value_of(&text, "Content-Transfer-Encoding"),
        "quoted-printable",
        "an overlong line has to leave the 8bit path"
    );
    for line in text.split("\r\n") {
        assert!(line.len() <= MAX_LINE_MUST, "line of {} chars", line.len());
    }
    assert_eq!(Message::parse(&text).expect("parse").body, body);
}

#[test]
fn the_998_octet_boundary_is_inclusive() {
    let inside = "b".repeat(MAX_LINE_MUST);
    let text = String::from_utf8(build("s", &inside)).expect("ascii");
    assert_eq!(value_of(&text, "Content-Transfer-Encoding"), "8bit");
    assert_eq!(body_of(&text), inside);

    let outside = "b".repeat(MAX_LINE_MUST + 1);
    let text = String::from_utf8(build("s", &outside)).expect("ascii");
    assert_eq!(
        value_of(&text, "Content-Transfer-Encoding"),
        "quoted-printable"
    );
}

#[test]
fn a_non_ascii_body_goes_out_seven_bit() {
    // `8bit` is only safe when the next hop speaks 8BITMIME (RFC 6152) or
    // SMTPUTF8 (RFC 6532); quoted-printable needs nothing from it.
    let raw = build("s", "Grüße");
    let text = String::from_utf8(raw.clone()).expect("the renderer emits ASCII");
    assert_eq!(
        value_of(&text, "Content-Transfer-Encoding"),
        "quoted-printable"
    );
    assert_eq!(body_of(&text), "Gr=C3=BC=C3=9Fe");
    for line in text.split("\r\n") {
        assert!(
            line.len() <= MAX_QUOTED_PRINTABLE_LINE,
            "quoted-printable line of {} chars",
            line.len()
        );
    }
    assert_eq!(Message::parse(&text).expect("parse").body, "Grüße");
}

#[test]
fn a_short_ascii_body_keeps_the_senders_bytes() {
    let text = String::from_utf8(build("s", "Hallo\r\nWelt")).expect("ascii");
    assert_eq!(value_of(&text, "Content-Transfer-Encoding"), "8bit");
    assert_eq!(body_of(&text), "Hallo\r\nWelt");
}

#[test]
fn every_text_part_chooses_its_own_encoding() {
    let raw = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .subject("s")
        .body("Grüße")
        .html_body("<p>Grüße</p>")
        .attachment(Attachment::new("a.txt", "text/plain", b"x".to_vec()))
        .build()
        .expect("build")
        .render()
        .expect("render");
    let text = String::from_utf8(raw).expect("the renderer emits ASCII");
    assert_eq!(
        text.matches("Content-Transfer-Encoding: quoted-printable")
            .count(),
        2,
        "plain and html part"
    );
    assert_eq!(
        text.matches("Content-Transfer-Encoding: base64").count(),
        1,
        "the attachment"
    );
}

#[test]
fn the_encoder_escapes_what_the_wire_would_eat() {
    // RFC 2045 §6.7: `=` is the escape character, and a space or tab at the
    // end of a line would be stripped in transit.
    assert_eq!(transfer::encode_quoted_printable("a=b"), "a=3Db");
    assert_eq!(
        transfer::encode_quoted_printable("a \r\nb\t\r\n"),
        "a=20\r\nb=09\r\n"
    );
    // A lone CR or LF is a line break too, and leaves as CRLF.
    assert_eq!(transfer::encode_quoted_printable("a\rb\nc"), "a\r\nb\r\nc");
    assert_eq!(transfer::encode_quoted_printable("ä"), "=C3=A4");
    // A soft line break may fall between the bytes of one character: the
    // receiver concatenates them again.
    let text = "ß".repeat(200);
    let encoded = transfer::encode_quoted_printable(&text);
    assert!(encoded.is_ascii());
    assert!(encoded
        .split("\r\n")
        .all(|line| line.len() <= MAX_QUOTED_PRINTABLE_LINE));
    assert_eq!(transfer::decode_quoted_printable(&encoded), text.as_bytes());
}

proptest! {
    #[test]
    fn quoted_printable_round_trips_any_text(text in any::<String>()) {
        let normalised = text
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "\r\n");
        let encoded = transfer::encode_quoted_printable(&normalised);
        prop_assert!(encoded.is_ascii());
        prop_assert!(encoded
            .split("\r\n")
            .all(|line| line.len() <= MAX_QUOTED_PRINTABLE_LINE));
        prop_assert_eq!(
            transfer::decode_quoted_printable(&encoded),
            normalised.into_bytes()
        );
    }
}
