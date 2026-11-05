//! `InvalidMailbox` renders attacker-controlled mailbox text safely.
//!
//! The builder used to keep the whole `raw` argument, while the parser kept
//! only 120 bytes, so the same error had two different bounds depending on which
//! entry point saw the bad address. The payload is now capped in one private
//! constructor and `Display` escapes it, so neither the stored error nor the
//! rendered line can carry a control byte or grow without bound.

use mime_message::{parse, Error, Message};

#[test]
fn builder_display_escapes_controls_and_caps_the_payload() {
    let raw = format!("a@example.com\r\n\u{1b}{}", "x".repeat(10 * 1024));
    let error = Message::builder()
        .from(&raw)
        .expect_err("an address with controls is not a mailbox");

    let display = error.to_string();
    assert!(
        display.chars().all(|ch| !ch.is_control()),
        "Display must not emit a control byte: {display:?}"
    );
    assert!(
        display.chars().count() <= 120,
        "Display grew to {} chars: {display:?}",
        display.chars().count()
    );
    let Error::InvalidMailbox(payload) = error else {
        panic!("expected an invalid mailbox, got {error:?}");
    };
    assert!(
        payload.len() <= 120,
        "the builder path kept {} bytes",
        payload.len()
    );
}

#[test]
fn parser_caps_invalid_mailbox_on_the_wire_path() {
    let raw_address = format!("a@example.com\t{}", "x".repeat(200));
    let raw = format!("From: sender@example.com\r\nTo: {raw_address}\r\n\r\nx");
    let error = parse(&raw).expect_err("a whitespace address is not a mailbox");
    let display = error.to_string();
    assert!(
        display.chars().all(|ch| !ch.is_control()),
        "Display must not emit a control byte: {display:?}"
    );
    let Error::InvalidMailbox(payload) = error else {
        panic!("expected an invalid mailbox, got {error:?}");
    };
    assert!(
        payload.len() <= 120,
        "the parser path kept {} bytes",
        payload.len()
    );
}
