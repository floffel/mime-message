# mime-message

Build RFC 5322 / MIME email messages as bytes — no SMTP, no I/O, no async.

```rust
let raw = Message::builder()
    .from("Shop <shop@example.com>")?
    .to("kunde@example.com")?
    .subject("Ihre Rechnung")
    .body("Anbei die Rechnung.")
    .attachment(Attachment::new("rechnung.pdf", "application/pdf", pdf_bytes))
    .build()?
    .render()?;
```

Guarantees the tests pin down: CRLF line endings everywhere, header folding
below 78 characters, RFC 2047 encoding for non-ASCII subjects, base64
attachments in `multipart/mixed`, and **rejection of CR/LF in headers** so a
caller cannot be tricked into header injection via subject or filename.

Deterministic: no clock, no randomness — pass `Date` and `Message-ID` if you
need them.

Licensed under Apache-2.0 OR MIT.
