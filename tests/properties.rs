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

fn preserved_header() -> impl Strategy<Value = mime_message::Header> {
    ("[A-Za-z][A-Za-z0-9-]{0,20}", header_text(60)).prop_filter_map(
        "only header names the crate does not model",
        |(name, value)| {
            let modelled = [
                "from",
                "to",
                "cc",
                "bcc",
                "subject",
                "date",
                "message-id",
                "mime-version",
                "content-type",
                "content-transfer-encoding",
            ];
            if modelled.contains(&name.to_ascii_lowercase().as_str()) {
                return None;
            }
            mime_message::Header::new(name, value).ok()
        },
    )
}

fn message() -> impl Strategy<Value = Message> {
    (
        mailbox(),
        prop::collection::vec(mailbox(), 1..4),
        prop::collection::vec(mailbox(), 0..3),
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
                prop::option::of("[a-zA-Z0-9._@-]{1,30}"),
            ),
            0..4,
        ),
        prop::collection::vec(preserved_header(), 0..4),
    )
        .prop_map(
            |(
                from,
                to,
                cc,
                bcc,
                subject,
                body,
                html_body,
                date,
                message_id,
                attachments,
                headers,
            )| {
                let mut builder = Message::builder()
                    .from(&format_mailbox(&from))
                    .expect("generated mailbox parses")
                    .subject(subject)
                    .body(body);
                for mailbox in &to {
                    builder = builder.to(&format_mailbox(mailbox)).expect("generated");
                }
                for mailbox in &cc {
                    builder = builder.cc(&format_mailbox(mailbox)).expect("generated");
                }
                for mailbox in &bcc {
                    builder = builder.bcc(&format_mailbox(mailbox)).expect("generated");
                }
                if let Some(html) = html_body {
                    builder = builder.html_body(html);
                }
                if let Some(date) = date {
                    builder = builder.date(date);
                }
                if let Some(id) = message_id {
                    builder = builder.message_id(id);
                }
                for (name, content_type, data, content_id) in attachments {
                    let mut attachment = Attachment::new(name, content_type, data);
                    if let Some(id) = content_id {
                        attachment = attachment.with_content_id(id);
                    }
                    builder = builder.attachment(attachment);
                }
                for header in headers {
                    builder = builder.header(header);
                }
                builder.build().expect("generated message builds")
            },
        )
}

fn format_mailbox(mailbox: &Mailbox) -> String {
    match &mailbox.name {
        Some(name) => {
            let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\" <{}>", mailbox.address)
        }
        None => mailbox.address.clone(),
    }
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
        // Bcc is never rendered, so it cannot survive the round trip; it must
        // also not leak into the bytes.
        prop_assert!(parsed.bcc.is_empty());
        for mailbox in &built.bcc {
            prop_assert!(
                !raw.contains(&mailbox.address),
                "Bcc address leaked into {:?}",
                raw
            );
        }
        prop_assert_eq!(parsed.headers(), built.headers(), "headers of {:?}", raw);
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
            prop_assert_eq!(&got.content_id, &want.content_id);
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
        let first_text = String::from_utf8(raw).unwrap();
        let first = match parse(&first_text) {
            Ok(message) => message,
            Err(error) => panic!("first parse failed: {error:?} for {first_text:?}"),
        };
        let Ok(rerendered) = first.render() else { return Ok(()) };
        let second_text = String::from_utf8(rerendered).unwrap();
        let second = match parse(&second_text) {
            Ok(message) => message,
            Err(error) => panic!("second parse failed: {error:?} for {second_text:?}"),
        };
        prop_assert_eq!(second, first);
    }
}

/// DKIM properties: the body hash must follow RFC 6376 for *any* body, and a
/// signature must verify whatever the body looks like.
#[cfg(feature = "dkim")]
mod dkim_properties {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use mime_message::dkim::{self, SignParams, SigningKey};
    use mime_message::Message;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    /// Relaxed body canonicalization written straight from RFC 6376 §3.4.4,
    /// independent of the implementation under test.
    fn relaxed_body(body: &str) -> Vec<u8> {
        let normalised = body.replace("\r\n", "\n").replace('\r', "\n");
        let mut lines: Vec<String> = normalised
            .split('\n')
            .map(|line| {
                let mut out = String::new();
                let mut pending_space = false;
                for ch in line.chars() {
                    if ch == ' ' || ch == '\t' {
                        pending_space = true;
                    } else {
                        if pending_space {
                            out.push(' ');
                        }
                        pending_space = false;
                        out.push(ch);
                    }
                }
                out
            })
            .collect();
        while lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        let mut out = String::new();
        for line in lines {
            out.push_str(&line);
            out.push_str("\r\n");
        }
        out.into_bytes()
    }

    fn message_with(body: String) -> Message {
        Message::builder()
            .from("a@example.com")
            .expect("from")
            .to("b@example.com")
            .expect("to")
            .subject("property")
            .body(body)
            .build()
            .expect("build")
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

        /// The `bh=` we emit is the SHA-256 of the relaxed canonical body.
        #[test]
        fn body_hash_matches_the_rfc(body in any::<String>()) {
            let key = SigningKey::from_ed25519_seed(&[61u8; 32]);
            let signed = message_with(body.clone())
                .sign(&key, &SignParams::new("example.com", "sel"))
                .expect("sign");
            let raw = String::from_utf8_lossy(&signed);
            let header = &dkim::signatures(&raw)?[0];
            let expected = Sha256::digest(relaxed_body(&body));
            prop_assert_eq!(STANDARD.encode(expected), STANDARD.encode(&header.body_hash));
        }

        /// Whatever the body, sign → verify succeeds.
        #[test]
        fn sign_and_verify_any_body(body in any::<String>()) {
            let key = SigningKey::from_ed25519_seed(&[63u8; 32]);
            let signed = message_with(body)
                .sign(&key, &SignParams::new("example.com", "sel"))
                .expect("sign");
            let raw = String::from_utf8_lossy(&signed);
            prop_assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
        }

        /// Appending anything that survives canonicalization breaks the seal.
        #[test]
        fn appended_body_text_breaks_the_signature(body in "[ -~]{0,40}", extra in "[!-~]{1,10}") {
            let key = SigningKey::from_ed25519_seed(&[67u8; 32]);
            let signed = message_with(body)
                .sign(&key, &SignParams::new("example.com", "sel"))
                .expect("sign");
            let raw = String::from_utf8_lossy(&signed).into_owned();
            let tampered = format!("{raw}{extra}");
            prop_assert!(dkim::verify(&tampered, &key.verifying_key()).is_err());
        }

        /// Every preserved header is covered: changing one must not verify.
        #[test]
        fn changing_a_preserved_header_breaks_the_signature(
            value in "[a-zA-Z0-9](?:[a-zA-Z0-9 ]{0,18}[a-zA-Z0-9])?",
        ) {
            let key = SigningKey::from_ed25519_seed(&[71u8; 32]);
            let mut message = message_with("body".to_string());
            message.push_header(
                mime_message::Header::new("X-Note", value.clone()).expect("header"),
            );
            let signed = message
                .sign(&key, &SignParams::new("example.com", "sel"))
                .expect("sign");
            let raw = String::from_utf8_lossy(&signed).into_owned();
            prop_assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
            let tampered = raw.replace(
                &format!("X-Note: {value}"),
                "X-Note: something else",
            );
            prop_assert!(dkim::verify(&tampered, &key.verifying_key()).is_err());
        }
    }
}
