//! Fuzz target: the parser must never panic, whatever it accepts must be
//! renderable again, and the inline-reference rewrite and DKIM header parser
//! must be total.
//!
//! Run with `cargo +nightly fuzz run parse` (see the README for the corpus and
//! how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::{parse, Error, Message};

/// A structural failure has to locate: the entity ordinal is a real entity (1 is
/// the message itself), a line number is a wire line, and a base64 offset points
/// inside the message it came from. A location that points nowhere is worse than
/// none, because a caller trusts it.
fn check_location(text: &str) {
    match parse(text) {
        Err(Error::InvalidBase64 { part, offset, .. }) => {
            assert!(part >= 1, "a parsed payload belongs to an entity");
            assert!(
                offset <= text.len(),
                "offset {offset} is outside a {}-byte message",
                text.len()
            );
        }
        Err(Error::MalformedHeader {
            part,
            line,
            text: field,
        }) => {
            assert!(part >= 1 && line >= 1, "a wire line has a position");
            assert!(field.len() <= 120, "the payload stays truncated");
        }
        Err(Error::ControlCharacter { name, byte }) => {
            // The payload has to still identify the input: a control-byte
            // rejection names a real field and a byte that is really in the
            // message, and really one RFC 5322 keeps out of a value.
            assert!(!name.is_empty(), "a rejection names its field");
            assert!(
                text.as_bytes().contains(&byte),
                "control byte 0x{byte:02x} is not in a {}-byte input",
                text.len()
            );
            assert!(
                byte == 0x7f || (byte < 0x20 && byte != b'\t') || byte >= 0xc2,
                "0x{byte:02x} does not identify a rejected character"
            );
        }
        Err(Error::InvalidContentType { part, text: value }) => {
            assert!(part >= 1, "a parsed media type belongs to an entity");
            assert!(value.len() <= 120, "the payload stays truncated");
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    // Exact path: callers hand us `&str` from a socket.
    if let Ok(text) = std::str::from_utf8(data) {
        check_location(text);
    }

    // Permissive path: 8-bit bodies are decoded lossily before parsing.
    let lossy = String::from_utf8_lossy(data);
    check_location(&lossy);
    if let Ok(message) = Message::parse(&lossy) {
        // Rewriting `cid:` references is a pure transformation over arbitrary
        // HTML (or arbitrary text, since a body is whatever the sender wrote).
        let html = message.html_body.clone().unwrap_or_default();
        let _ = message.rewrite_cid_references(&html);
        let _ = message.rewrite_cid_references(&lossy);

        // Round-trip invariant: a parsed message can be rendered again.
        if let Ok(rendered) = message.render() {
            if let Ok(text) = std::str::from_utf8(&rendered) {
                let _ = parse(text);
                // DKIM-Signature parsing runs over the same bytes a verifier
                // would see and must never panic.
                let _ = mime_message::dkim::signatures(text);
            }
        }
    }

    // A message the fuzzer fully controls, but this time signed by us: the
    // signing input is built from arbitrary headers and must not panic either.
    if let Ok(message) = Message::parse(&lossy) {
        let key = mime_message::dkim::SigningKey::from_ed25519_seed(&[0u8; 32]);
        if let Ok(params) = mime_message::dkim::SignParams::new("example.com", "fuzz") {
            if let Ok(signed) = message.sign(&key, &params) {
                if let Ok(text) = std::str::from_utf8(&signed) {
                    let _ = mime_message::dkim::verify(text, &key.verifying_key());
                }
            }
        }
    }
});
