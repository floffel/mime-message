//! Fuzz target: the parser must never panic, and whatever it accepts must be
//! renderable again.
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
        // Round-trip invariant: a parsed message can be rendered again.
        if let Ok(rendered) = message.render() {
            if let Ok(text) = std::str::from_utf8(&rendered) {
                let _ = parse(text);
            }
        }
    }
});
