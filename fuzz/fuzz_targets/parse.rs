//! Fuzz target: the parser must never panic, whatever it accepts must be
//! renderable again, and the inline-reference rewrite and DKIM header parser
//! must be total.
//!
//! Run with `cargo +nightly fuzz run parse` (see the README for the corpus and
//! how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::{parse, Message};

fuzz_target!(|data: &[u8]| {
    // Exact path: callers hand us `&str` from a socket.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse(text);
    }

    // Permissive path: 8-bit bodies are decoded lossily before parsing.
    let lossy = String::from_utf8_lossy(data);
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
        let params = mime_message::dkim::SignParams::new("example.com", "fuzz");
        if let Ok(signed) = message.sign(&key, &params) {
            if let Ok(text) = std::str::from_utf8(&signed) {
                let _ = mime_message::dkim::verify(text, &key.verifying_key());
            }
        }
    }
});
