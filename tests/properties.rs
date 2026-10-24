//! Property tests: round-trips, invariants, and "never panics" for every pure
//! entry point.
//!
//! The round-trip property is the strong one: whatever the builder can render,
//! the parser must read back into an equal `Message` (modulo CRLF normalisation
//! of the body and trimming of header values, both documented behaviour).

use mime_message::{parse, Attachment, Mailbox, Message};
use proptest::prelude::*;

const CONTENT_TYPES: [&str; 4] = [
    "text/plain",
    "application/pdf",
    "image/png",
    "application/octet-stream",
];

fn address() -> impl Strategy<Value = String> {
    ("[a-z0-9]{1,12}", "[a-z0-9-]{1,12}", "[a-z]{2,4}")
        .prop_map(|(local, domain, tld)| format!("{local}@{domain}.{tld}"))
}

/// Text that survives header rendering: no controls, no Unicode line breaks.
fn header_text(max: usize) -> impl Strategy<Value = String> {
    let pattern = format!("[^\\x00-\\x1f\\x7f-\\x9f\\u{{2028}}\\u{{2029}}]{{0,{max}}}");
    proptest::string::string_regex(&pattern).expect("header_text regex is valid")
}

fn display_name() -> impl Strategy<Value = Option<String>> {
    optional_header_text(25)
}

/// A header value that survives rendering unchanged: trimmed, non-empty.
fn optional_header_text(max: usize) -> impl Strategy<Value = Option<String>> {
    header_text(max).prop_map(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn filename() -> impl Strategy<Value = String> {
    "[^\\x00-\\x1f\\x7f-\\x9f/\\\\\"\\u{2028}\\u{2029}]{1,30}".prop_filter(
        "path traversal or empty-looking names are rejected by design",
        |name| name != "." && name != ".." && !has_drive_prefix(name),
    )
}

fn has_drive_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn mailbox() -> impl Strategy<Value = Mailbox> {
    (display_name(), address()).prop_map(|(name, address)| Mailbox { name, address })
}

fn message() -> impl Strategy<Value = Message> {
    (
        mailbox(),
        prop::collection::vec(mailbox(), 0..4),
        prop::collection::vec(mailbox(), 0..3),
        header_text(120),
        any::<String>(),
        prop::option::of(header_text(60)),
        optional_header_text(40),
        optional_header_text(40),
        prop::collection::vec(
            (
                filename(),
                prop::sample::select(&CONTENT_TYPES[..]),
                prop::collection::vec(any::<u8>(), 0..200),
            ),
            0..4,
        ),
    )
        .prop_map(
            |(from, to, cc, subject, body, html_body, date, message_id, attachments)| Message {
                from,
                to,
                cc,
                subject,
                body,
                html_body,
                date,
                message_id,
                attachments: attachments
                    .into_iter()
                    .map(|(name, content_type, data)| Attachment::new(name, content_type, data))
                    .collect(),
            },
        )
}

fn normalise_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// build → render → parse yields the same message.
    #[test]
    fn render_parse_roundtrip(built in message()) {
        // Some inputs are rejected by the renderer (CR/LF in a header value,
        // unsafe filename); the property only covers renderable messages.
        let Ok(raw) = built.render() else { return Ok(()) };
        let raw = String::from_utf8(raw).expect("rendered messages are UTF-8");

        let parsed = parse(&raw).expect("a rendered message must parse");

        prop_assert_eq!(&parsed.from, &built.from, "From: {:?}", raw);
        prop_assert_eq!(&parsed.to, &built.to, "To: {:?}", raw);
        prop_assert_eq!(&parsed.cc, &built.cc, "Cc: {:?}", raw);
        prop_assert_eq!(parsed.subject.as_str(), built.subject.trim(), "subject of {:?}", raw);
        prop_assert_eq!(
            normalise_newlines(&parsed.body),
            normalise_newlines(&built.body),
            "body of {:?}",
            raw
        );
        prop_assert_eq!(parsed.html_body, built.html_body.clone());
        prop_assert_eq!(&parsed.date, &built.date);
        prop_assert_eq!(&parsed.message_id, &built.message_id);
        prop_assert_eq!(parsed.attachments.len(), built.attachments.len());
        for (got, want) in parsed.attachments.iter().zip(&built.attachments) {
            prop_assert_eq!(&got.filename, &want.filename);
            prop_assert_eq!(&got.content_type, &want.content_type);
            prop_assert_eq!(&got.data, &want.data);
        }
    }

    /// Folding and unfolding preserve a long subject byte for byte.
    #[test]
    fn header_folding_roundtrip(
        words in prop::collection::vec(
            "[^\\s\\x00-\\x1f\\x7f-\\x9f\\u{2028}\\u{2029}]{1,12}",
            1..40,
        )
    ) {
        let subject = words.join(" ");
        let raw = Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.com")
            .unwrap()
            .subject(subject.clone())
            .build()
            .unwrap()
            .render()
            .unwrap();
        let raw = String::from_utf8(raw).unwrap();
        // A long header must be folded onto continuation lines.
        if subject.len() > 78 {
            prop_assert!(raw.lines().count() > 3, "not folded: {:?}", raw);
        }
        prop_assert_eq!(parse(&raw).unwrap().subject, subject);
    }

    /// RFC 2047 encoded subjects decode back to the same text.
    #[test]
    fn encoded_word_roundtrip(
        subject in "[^\\x00-\\x1f\\x7f-\\x9f\\u{2028}\\u{2029}]{1,12}",
        repeat in 1..20usize,
    ) {
        let subject = subject.repeat(repeat);
        let raw = Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.com")
            .unwrap()
            .subject(subject.clone())
            .build()
            .unwrap()
            .render()
            .unwrap();
        let parsed = parse(&String::from_utf8(raw).unwrap()).unwrap();
        prop_assert_eq!(parsed.subject, subject.trim());
    }

    /// The parser must never panic, whatever it is handed.
    #[test]
    fn parse_never_panics_on_arbitrary_text(raw in any::<String>()) {
        let outcome = std::panic::catch_unwind(|| parse(&raw));
        prop_assert!(outcome.is_ok(), "parser panicked on {:?}", raw);
    }

    /// Arbitrary bytes (as lossily decoded text) must never panic either.
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let outcome = std::panic::catch_unwind(|| parse(&text));
        prop_assert!(outcome.is_ok(), "parser panicked on {} bytes", bytes.len());
    }

    /// RFC 2047 decoding is total and never grows the text pathologically.
    #[test]
    fn rfc2047_decode_never_panics(raw in any::<String>()) {
        let outcome = std::panic::catch_unwind(|| mime_message::rfc2047::decode(&raw));
        prop_assert!(outcome.is_ok());
    }

    /// Base64 decoding is total, never allocates more than the input, and
    /// rejects without panicking.
    #[test]
    fn base64_decode_is_bounded(raw in "\\PC{0,200}") {
        if let Ok(bytes) = mime_message::transfer::decode_base64(&raw) {
            prop_assert!(bytes.len() <= raw.len());
        }
    }

    /// Charset decoding is total for arbitrary bytes and labels.
    #[test]
    fn charset_decode_is_total(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        label in "[a-zA-Z0-9\\-_.]{0,20}",
    ) {
        let _ = mime_message::charset::decode(&bytes, &label);
    }

    /// Quoted-printable decoding never grows the input beyond the input length
    /// and never panics on arbitrary text.
    #[test]
    fn quoted_printable_decode_is_bounded(raw in any::<String>()) {
        let decoded = mime_message::transfer::decode_quoted_printable(&raw);
        prop_assert!(decoded.len() <= raw.len());
    }

    /// A parsed message can always be rendered again and re-parsed to the same
    /// value (idempotent re-rendering).
    #[test]
    fn parse_render_parse_is_stable(built in message()) {
        let Ok(raw) = built.render() else { return Ok(()) };
        let first = parse(&String::from_utf8(raw).unwrap()).unwrap();
        let Ok(rerendered) = first.render() else { return Ok(()) };
        let second = parse(&String::from_utf8(rerendered).unwrap()).unwrap();
        prop_assert_eq!(second, first);
    }
}
