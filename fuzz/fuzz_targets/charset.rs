//! Fuzz target: charset decoding is total for arbitrary bytes and labels.
//!
//! Run with `cargo +nightly fuzz run charset`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::charset;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let _ = charset::decode(data, "");
        return;
    }

    // A leading byte chooses the split, so one input controls both the label and
    // the payload. The label is decoded lossily because `decode` takes `&str`,
    // while the payload remains arbitrary bytes.
    let split = usize::from(data[0]) % data.len();
    let (label, payload) = data.split_at(split);
    let label = String::from_utf8_lossy(label);
    let _ = charset::decode(payload, &label);

    // Also feed the full byte string through a few labels that exercise
    // different decoder families and replacement paths.
    for label in ["utf-8", "utf-16", "iso-8859-1", "windows-1252", "shift_jis"] {
        let _ = charset::decode(data, label);
    }

    // If the input itself is a valid label, use it for an empty payload too.
    if let Ok(label) = std::str::from_utf8(data) {
        let _ = charset::decode(&[], label);
    }
});
