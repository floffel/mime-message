# mime-message

Build **and parse** RFC 5322 / MIME email messages — no SMTP, no I/O, no async,
no `unsafe`.

```rust
let raw = Message::builder()
    .from("Shop <shop@example.com>")?
    .to("kunde@example.com")?
    .subject("Ihre Rechnung")
    .body("Anbei die Rechnung.")
    .attachment(Attachment::new("rechnung.pdf", "application/pdf", pdf_bytes))
    .build()?
    .render()?;

// … and back again.
let message = Message::parse(std::str::from_utf8(&raw)?)?;
assert_eq!(message.attachments[0].filename, "rechnung.pdf");
```

Deterministic: no clock, no randomness — pass `Date` and `Message-ID` if you
need them. Parsing is pure, `Send`/`Sync`-clean and safe to run from many
threads at once.

## Rendering

Guarantees the tests pin down: CRLF line endings everywhere, header folding
below 78 characters without losing whitespace, RFC 2047 encoding for non-ASCII
subjects and display names, base64 attachments, `multipart/alternative` when an
HTML body is supplied, and **rejection of CR/LF in headers** so a caller cannot
be tricked into header injection via subject or filename.

## Parsing

`parse()` returns a [`Message`] for the whole RFC 5322 + MIME surface this crate
claims:

- Header block: CRLF / LF / bare-CR line endings, folded (tab or space)
  continuation lines, comments, quoted display names, groups
  (`Team: a@b, c@d;`), duplicate `To:`/`Cc:` headers joined, and duplicate
  structural headers rejected.
- RFC 2047 decoding: `B` and `Q` encodings, adjacent encoded-words joined
  across line folds, mixed charsets per word, unknown charsets and unparseable
  words passed through verbatim rather than dropped.
- Charsets: UTF-8, US-ASCII, ISO-8859-1, ISO-8859-15, Windows-1252, UTF-16 LE/BE;
  unknown labels fall back to UTF-8 with replacement characters.
- Transfer encodings: `base64` (wrapped, unpadded and mixed-case input
  accepted), `quoted-printable` (soft line breaks), `7bit`/`8bit`/`binary`.
- `multipart/mixed`, `multipart/alternative` and `multipart/related`, nested
  arbitrarily: the first non-attachment `text/plain` part becomes the body, the
  first `text/html` part becomes `html_body`, every other leaf part becomes an
  attachment with its decoded bytes.
- `Content-Type` parameters, including `charset` and `name`, plus RFC 2231
  extended and continued parameters (`filename*=utf-8''…`, `filename*0*`,
  `filename*1*`).
- `Content-Disposition: attachment` filenames, with path-traversal attempts
  rejected.

### Limits and safety

Everything malicious is a typed `Error`, never a panic or an OOM:

| Attack | Result |
| --- | --- |
| CR, LF, NUL, U+0085/U+2028/U+2029 smuggled through an encoded-word | `HeaderInjection` |
| Control characters in a header value | `ControlCharacter` |
| Duplicate `Content-Type` / `Content-Transfer-Encoding` (content-type smuggling) | `DuplicateHeader` |
| Deep `multipart` nesting | `LimitExceeded { what: "nesting depth" }` |
| Thousands of parts | `LimitExceeded { what: "part count" }` |
| Huge bodies or base64 bombs | `LimitExceeded { what: "body bytes" }` |
| Overlong header line / block / too many headers | `LimitExceeded { … }` |
| Truncated multipart | `UnterminatedMultipart` |
| `filename="../../etc/passwd"`, drive-relative `C:x`, backslash paths | `UnsafeFilename` |
| Invalid base64 | `InvalidBase64` |

Defaults (see [`Limits`]): 32 levels of nesting, 1000 entities, 64 KiB of
headers, 8 KiB per header line, 1000 header fields, 8 MiB per decoded body.
`parse_with_limits()` takes tighter budgets.

### Deliberate exclusions

Documented rather than silently missing:

- **No DKIM signing, no S/MIME.** Different problem, needs crypto dependencies.
- **`Bcc:` is not exposed.** A parsed `Bcc` must never be re-sent; it is dropped
  on purpose.
- **Unknown headers are not preserved.** The parser validates them but does not
  keep them, so a re-render is not a byte-perfect forward.
- **Inline `cid:` references are not rewritten.** `multipart/related` parts come
  back as attachments; hooking them up to HTML is the caller's job.
- **Not a streaming parser.** The whole message must be in memory; the size
  limits bound it. Reading from a socket is the caller's choice.
- **Charset set is closed.** Anything outside the list above is decoded as
  UTF-8-with-replacement, which is what real mail needs in practice.

## Tests

- Unit, integration, edge-case-matrix and security tests per function:
  empty input, headers-only, no body, CRLF/LF/CR, tab folding, 8-bit body,
  invalid base64, truncated multipart, unknown transfer encoding, 1000
  recipients, nesting/size bombs, concurrency (16 threads).
- Property tests (`proptest`): arbitrary `Message` → render → parse round-trip,
  header folding round-trip, RFC 2047 round-trip, `parse` never panics on
  arbitrary text *or* arbitrary bytes, base64/quoted-printable output bounded by
  input, charset decoding total.
- Doctests on every public item; `#![deny(missing_docs)]`,
  `#![forbid(unsafe_code)]`.
- Line coverage: **98.2 %** (`cargo llvm-cov --all-features --summary-only`);
  CI fails below 95 %.

### Fuzzing

```
cargo +nightly fuzz build parse       # CI builds this target
cargo +nightly fuzz run parse         # run it (seeds: fuzz/corpus/parse)
cargo +nightly fuzz run parse fuzz/artifacts/parse/<crash>   # reproduce
```

The target parses arbitrary bytes both as UTF-8 and lossily, then re-renders and
re-parses whatever was accepted. Seed corpus: `simple.eml`, `multipart.eml`
(nested mixed + alternative + RFC 2231 filename), `folded.eml` (folding, Q
encoding, quoted-printable), `truncated.eml`.

## License

Apache-2.0 OR MIT.
