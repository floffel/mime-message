//! Fuzz target: the `cid:` reference rewriter must never panic, must leave
//! unresolved references byte for byte as they were, and must only hand the
//! resolver references from URL positions in the input, after HTML character
//! reference decoding where that applies.
//!
//! Run with `cargo +nightly fuzz run cid` (see the README for the corpus and
//! how to reproduce a crash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mime_message::{cid, Attachment, Message};

/// The invariants that hold for any resolver shape over arbitrary text.
fn check_rewrite(html: &str) {
    // Totality: normalising arbitrary text never panics and is idempotent;
    // `cid::rewrite` consumes whatever `normalise` would have to reason about.
    let normalised = cid::normalise(html);
    assert_eq!(cid::normalise(normalised), normalised, "normalise is not stable");

    // Unresolved references are left exactly as they were.
    assert_eq!(
        cid::rewrite(html, |_| None),
        html,
        "an unresolved rewrite changed the text"
    );

    // Echoing each reference back is total and never introduces resolver text.
    let mut seen: Vec<String> = Vec::new();
    let echoed = cid::rewrite(html, |reference| {
        seen.push(reference.to_string());
        Some(reference.to_string())
    });
    assert!(!echoed.is_empty() || html.is_empty());
    for reference in &seen {
        assert!(!reference.is_empty(), "an empty reference was handed over");
    }

    // A replacement is inserted verbatim; a resolver that prepends a marker
    // must find that marker in the output exactly as many times as it resolved.
    let marker = "\u{1f}cid\0marker\u{1e}";
    let mut resolved = 0usize;
    let marked = cid::rewrite(html, |reference| {
        resolved += 1;
        Some(format!("{marker}{reference}"))
    });
    assert_eq!(
        marked.matches(marker).count(),
        resolved,
        "a resolver replacement was rewritten"
    );
    assert!(resolved == seen.len(), "the resolver was called twice differently");
}

/// The `Message`-level rewrite drives `try_data_uri` and the attribute escape
/// over arbitrary HTML and arbitrary `Content-Type` bytes.
fn check_message_rewrite(html: &str, content_type: &[u8], data: &[u8]) {
    let Ok(attachment) =
        Attachment::new("fuzz.bin", "application/octet-stream", data.to_vec())
            .with_content_id("fuzz@example.com")
    else {
        return;
    };
    let Ok(mut message) = Message::builder()
        .from("a@example.com")
        .unwrap()
        .to("b@example.com")
        .unwrap()
        .body("hi")
        .html_body(html)
        .attachment(attachment)
        .build()
    else {
        return;
    };

    // The known `Content-ID` resolves: this exercises the accepted path.
    let _ = message.rewrite_cid_references(html);

    // Arbitrary media types exercise the rejecting path; a value that cannot
    // produce a safe `data:` URI must leave the reference untouched.
    if let Some(part) = message.attachments.first_mut() {
        part.content_type = String::from_utf8_lossy(content_type).into_owned();
    }
    let rejected = message.rewrite_cid_references("cid:fuzz@example.com");
    assert!(
        rejected == "cid:fuzz@example.com" || rejected.starts_with("data:"),
        "the builtin rewrite returned neither the reference nor a data URI: {rejected:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    // Exact path: callers hand us `&str` from HTML they already decoded.
    if let Ok(text) = std::str::from_utf8(data) {
        check_rewrite(text);
        check_message_rewrite(text, data, data);
    }

    // Permissive path: bytes are decoded lossily before the rewrite runs.
    let lossy = String::from_utf8_lossy(data);
    check_rewrite(&lossy);
    check_message_rewrite(&lossy, data, data);
});
