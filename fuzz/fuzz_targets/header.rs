//! Fuzz target: the header-block path must never panic on arbitrary bytes.
//!
//! `parse_header_block` is private, so this drives the public `parse` entry
//! point with default `Limits`; the arbitrary bytes are appended to a valid
//! `From:` line, which keeps the parser on the header path until the input's
//! own blank line, if any.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::{parse, Header, Message};

fn check_header(header: &Header) {
    let value = header.value();
    assert!(
        !value.chars().any(|ch| {
            matches!(ch, '\r' | '\n' | '\0' | '\u{85}' | '\u{2028}' | '\u{2029}')
                || (ch.is_control() && ch != '\t')
        }),
        "accepted value contains a forbidden line separator or control: {value:?}"
    );
    assert_eq!(
        value.trim_matches(|ch| ch == ' ' || ch == '\t'),
        value,
        "accepted value is not WSP-trimmed"
    );

    let raw_value = header.raw_value();
    if !raw_value.is_empty() {
        assert!(
            raw_value
                .rsplit("\r\n")
                .next()
                .is_some_and(|line| !line.is_empty()),
            "raw value ends with an empty physical line: {raw_value:?}"
        );
    }

    let rebuilt = Header::new(header.name(), value).expect("accepted value revalidates");
    assert_eq!(rebuilt.value(), value);
}

fn check_message(message: &Message) {
    for header in message.headers() {
        check_header(header);
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let raw = format!("From: fuzz@example.com\r\n{text}\r\n\r\n");
    if let Ok(message) = parse(&raw) {
        check_message(&message);
    }
});
