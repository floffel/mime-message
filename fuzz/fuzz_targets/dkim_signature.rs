//! Fuzz target: DKIM signature and verification parsers must be total over
//! attacker-shaped message text, including body-length and fold boundaries.
//!
//! Run with `cargo +nightly fuzz run dkim_signature`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::dkim::{self, SigningKey};

const MAX_LINE: usize = 78;
const MAX_LINE_HARD: usize = 998;

fn key() -> SigningKey {
    SigningKey::from_ed25519_seed(&[0u8; 32])
}

fn check_text(text: &str) {
    let key = key();
    let _ = dkim::signatures(text);
    let _ = dkim::verify(text, &key.verifying_key());
}

fn signature_with_length(body: &str, length: usize) -> String {
    format!(
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; \
         d=example.com; s=fuzz; h=from; bh=AA==; b=AA==; l={length}\r\n\
         From: fuzz@example.com\r\n\
         \r\n\
         {body}",
    )
}

fn exercise_body_lengths(body: &str) {
    let len = body.len();
    for length in [0, len.saturating_sub(1), len, len.saturating_add(1)] {
        let raw = signature_with_length(body, length);
        check_text(&raw);
    }
}

fn signature_with_folded_header_name(width: usize, body: &str) -> String {
    let header_name = "x".repeat(width);
    format!(
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; \
         d=example.com; s=fuzz; h=from:{header_name}; bh=AA==; b=AA==\r\n\
         From: fuzz@example.com\r\n\
         \r\n\
         {body}",
    )
}

fn exercise_fold_limits(body: &str) {
    for width in [
        0,
        MAX_LINE.saturating_sub(1),
        MAX_LINE + 1,
        MAX_LINE_HARD.saturating_sub(1),
        MAX_LINE_HARD + 1,
    ] {
        let raw = signature_with_folded_header_name(width, body);
        check_text(&raw);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        check_text(text);
    }

    let lossy = String::from_utf8_lossy(data);
    check_text(&lossy);
    exercise_body_lengths(&lossy);
    exercise_fold_limits(&lossy);
});
