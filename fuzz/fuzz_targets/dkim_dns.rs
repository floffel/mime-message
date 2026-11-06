//! Fuzz target: DKIM DNS TXT records are attacker-controlled input and must be
//! rejected without panics, including tag values around RFC line limits.
//!
//! Run with `cargo +nightly fuzz run dkim_dns`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::dkim::VerifyingKey;

const MAX_LINE: usize = 78;
const MAX_LINE_HARD: usize = 998;

fn check_text(text: &str) {
    let _ = VerifyingKey::from_dns_record(text);
}

fn exercise_fold_limits() {
    for width in [
        0,
        MAX_LINE.saturating_sub(1),
        MAX_LINE + 1,
        MAX_LINE_HARD.saturating_sub(1),
        MAX_LINE_HARD + 1,
    ] {
        let record = format!("v=DKIM1; k=rsa; p={}", "A".repeat(width));
        check_text(&record);
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        check_text(text);
    }

    let lossy = String::from_utf8_lossy(data);
    check_text(&lossy);
    exercise_fold_limits();
});
