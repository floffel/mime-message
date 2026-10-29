# mime-message

Build **and parse** RFC 5322 / MIME email messages — no SMTP, no I/O, no async,
no `unsafe`, no network access. Optional DKIM signing and verification behind a
feature flag.

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
need them, and a DKIM timestamp if you want one. Parsing is pure, `Send`/`Sync`-
clean and safe to run from many threads at once.

## Examples

[`examples/compose_and_parse.rs`](examples/compose_and_parse.rs) composes an
invoice mail — text plus an HTML alternative, an inline logo with a
`Content-ID` and a PDF attachment — then parses the rendered bytes back and
asserts the round trip:

```
cargo run --example compose_and_parse
```

CI builds and runs it, so the example cannot rot.

## Rendering

Guarantees the tests pin down: CRLF line endings everywhere, header folding
below 78 characters without losing whitespace (the headers of the MIME parts
included), RFC 2047 encoding for non-ASCII
subjects and display names, base64 attachments, `multipart/alternative` when an
HTML body is supplied, `multipart/related` when every attachment carries a
`Content-ID`, and **rejection of CR/LF in headers** so a caller cannot be
tricked into header injection through subject, filename or `Content-ID`.

Header fields the crate does not model (`Reply-To`, `In-Reply-To`,
`List-Unsubscribe`, `Authentication-Results`, any `X-…`) are rendered from the
stored bytes, so a parsed message can be forwarded without losing them.
`Bcc:` is parsed into `Message::bcc` and **never rendered**: the caller puts
those addresses into the SMTP envelope, which is what makes a blind copy blind.

### Line limits and transfer encoding

Three numbers govern what the next hop accepts, and each one is enforced rather
than hoped for:

- **78 characters** per header line is the RFC 5322 §2.1.1 *should*. Every header
  — including the headers of the MIME parts — is folded at a space.
- **998 octets** per line is the *must* in the same section. A body whose longest
  line is longer is sent as `quoted-printable`, where soft line breaks keep every
  line within 76 characters (RFC 2045 §6.7) and the decoded body is exactly the
  one the caller supplied.
- **75 characters** per encoded-word is RFC 2047 §2. A long non-ASCII subject is
  split into several `=?UTF-8?B?…?=` words; each one decodes on its own, and the
  concatenation is the original subject.

`Content-Transfer-Encoding: 8bit` is used for an ASCII body within the limit and
otherwise never: `8bit` is only legal when the next hop speaks 8BITMIME (RFC 6152)
or SMTPUTF8 (RFC 6532), while quoted-printable needs nothing from it. Any
non-ASCII byte or any overlong line therefore switches that text part to
quoted-printable. Attachments are always base64, wrapped at 76 characters.

## Parsing

`parse()` returns a [`Message`] for the whole RFC 5322 + MIME surface this crate
claims:

- Header block: CRLF / LF / bare-CR line endings, folded (tab or space)
  continuation lines, comments, quoted display names, groups
  (`Team: a@b, c@d;`), duplicate `To:`/`Cc:`/`Bcc:` headers joined, and duplicate
  structural headers rejected.
- **Unknown headers preserved**: every field the crate does not model is kept in
  wire order with its original name casing, spacing and folding, and re-rendered
  byte for byte (`Message::headers()`, `Message::header(name)`). Duplicates are
  kept as separate entries; modelled headers are not duplicated.
- RFC 2047 decoding: `B` and `Q` encodings, adjacent encoded-words joined
  across line folds, mixed charsets per word, unknown charsets and unparseable
  words passed through verbatim rather than dropped.
- Charsets: every label the WHATWG encoding registry knows (`encoding_rs`) - UTF-8,
  UTF-16 LE/BE, ISO-8859-1 … -16, Windows-1251/1252, KOI8-R/U, Shift_JIS,
  GBK/GB18030, Big5, EUC-JP/KR, … - plus the spellings real mail uses that the
  registry does not list (`utf16`, `utf16be`, `latin9`). RFC 2978 asks receivers to
  be liberal about labels: US-ASCII and ISO-8859-1 decode as Windows-1252 the way
  mail clients do, and unknown or empty labels fall back to UTF-8 with replacement
  characters instead of failing the parse.
- Transfer encodings: `base64` (wrapped, unpadded and mixed-case input
  accepted), `quoted-printable` (soft line breaks), `7bit`/`8bit`/`binary`.
- `multipart/mixed`, `multipart/alternative` and `multipart/related`, nested
  arbitrarily: the first non-attachment `text/plain` part becomes the body, the
  first `text/html` part becomes `html_body`, every other leaf part becomes an
  attachment with its decoded bytes and its `Content-ID`.
- `Content-Type` parameters, including `charset` and `name`, plus RFC 2231
  extended and continued parameters (`filename*=utf-8''…`, `filename*0*`,
  `filename*1*`).
- `Content-Disposition: attachment` filenames, with path-traversal attempts
  rejected.

### Inline `cid:` parts

`Attachment::content_id` holds the part's `Content-ID` (without angle brackets),
and the caller decides how a reference is resolved — nothing is fetched:

```rust
let part = message.part_by_content_id("cid:logo@example.com");     // no network
let html = message.rewrite_cid_references(&original_html);         // data: URIs
let html = cid::rewrite(&original_html, |reference| {              // or your URLs
    message.part_by_content_id(reference).map(|part| format!("/inline/{reference}"))
});
```

Lookups strip the `cid:` scheme and angle brackets, so `logo`, `cid:logo` and
`cid:<logo>` find the same part; comparison is case-sensitive (RFC 2392).
Unresolved references are left untouched instead of being dropped, and
`cid::data_uri()` is there when a caller wants the `data:` form explicitly.

### Limits and safety

Everything malicious is a typed `Error`, never a panic or an OOM:

| Attack | Result |
| --- | --- |
| CR, LF, NUL, U+0085/U+2028/U+2029 smuggled through an encoded-word | `HeaderInjection` |
| Control characters in a header value | `ControlCharacter` |
| Duplicate `Content-Type` / `Content-Transfer-Encoding` (content-type smuggling) | `DuplicateHeader` |
| A preserved header that would duplicate a modelled one (`Subject`, `Content-Type`, …) | `DuplicateHeader` |
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

`max_depth` counts `multipart` containers, not entities: the top-level entity is
depth 0, a leaf part is accepted at any depth a container already reached, and a
body that is not multipart never meets the limit. `max_depth = 0` therefore still
parses a flat message (plus a single container) and only refuses nesting.

## DKIM (`dkim` feature)

```toml
mime-message = { version = "0.3", features = ["dkim"] }
```

RFC 6376 `rsa-sha256` and RFC 8463 `ed25519-sha256`, `simple` and `relaxed`
canonicalization for headers and body, signing and verification:

```rust,no_run
use mime_message::dkim::{self, SignParams, SigningKey, VerifyingKey};

let key = SigningKey::from_pem(&std::fs::read_to_string("dkim-private.pem")?)?;
let signed = message.sign(&key, &SignParams::new("example.com", "mail").timestamp(1_700_000_000))?;

// Verification runs over the received bytes: re-rendering destroys a
// signature, so it takes `&str`, not a `Message`.
let key = VerifyingKey::from_dns_record("v=DKIM1; k=rsa; p=MIGf…")?;
let signature = dkim::verify(std::str::from_utf8(&signed)?, &key)?;
assert_eq!(signature.domain, "example.com");
```

- Keys: PKCS#1 and PKCS#8 RSA PEM, PKCS#8 Ed25519 PEM, a 32-byte Ed25519 seed
  (raw or base64) and DNS TXT records (`v=DKIM1; k=rsa|ed25519; p=…`). RSA keys
  below 1024 bits are rejected (RFC 8301), as are revoked (`p=`) records, unknown
  key types and unparseable base64 — all `Error::InvalidKey`, which never
  contains key material.
- Signing is deterministic: the timestamp is a parameter, header order comes from
  the rendered message, and `h=` lists every field present, duplicates once per
  occurrence so a receiver's bottom-up instance selection covers each one. `Bcc`
  is not signed because it is not sent.
- Verification compares `bh=` in constant time (`subtle`), honours `l=`,
  selects header instances bottom-up per RFC 6376 §5.4.2, treats an over-signed
  name as the empty string, and uses Ed25519 `verify_strict` or RSA PKCS#1 v1.5.
  It returns the first signature that verifies, otherwise the first failure:
  `MissingSignature`, `NoMatchingSignature`, `BodyHashMismatch`,
  `SignatureMismatch`, `InvalidSignature`.
- No DNS, no OCSP, no key cache, no clock. `Debug` on `SigningKey` prints the
  algorithm only.
- Known dependency advisory: `rsa` 0.9 carries RUSTSEC-2023-0071 (the "Marvin"
  timing side channel in PKCS#1 v1.5 *decryption* padding, no upstream fix yet).
  This crate never decrypts — it signs with a caller-supplied key and verifies
  with public keys — so that path is unreachable; the ignore and its reasoning
  live in `deny.toml`.

**Test-vector status.** RFC 8463 Appendix A.3 verifies for *both* of its
signatures (RSA and Ed25519) with the published public keys, and the Ed25519
signature is reproduced **byte for byte** from the published seed — that pins
canonicalization, `h=` handling and the hash-then-sign rule against the RFC.
`simple/simple` is pinned by hand-written canonical inputs in `src/dkim.rs`
(RFC 6376 §3.4.1). **Gap:** RFC 6376 Appendix A.2 is *not* used as a vector — its
`b=` value does not verify against the message printed next to it under any
reconstruction of the folding we tried, and its private key is redacted, so that
figure is illustrative only. We would rather say so than ship a test that passes
by fitting the implementation to a guess.

## Deliberate exclusions

Documented rather than silently missing:

- **Not a streaming parser.** The whole message must be in memory; the size
  limits bound it. Reading from a socket is the caller's choice. This stays out
  of scope, not scheduled.
- **No DNS lookup during DKIM verification.** Fetching
  `selector._domainkey.domain` is the caller's job: this crate does no I/O, and a
  resolver would bring its own trust model.
- **No S/MIME, no OpenPGP.** Different problem, different threat model.
- **No `rsa-sha1`, no `l=` on signing.** RFC 8301 deprecates SHA-1 and `l=` only
  weakens a signature. Both are still parsed (and `l=` honoured) on the
  verification side, because real mail carries them.
- **No charset sniffing.** A missing or unknown `charset` label falls back to
  UTF-8-with-replacement; the bytes are never sniffed for encoding. Every label
  the WHATWG registry knows *is* resolved (see *Charsets* above), so what is
  excluded is guessing, not coverage.
- **Unknown headers are preserved, not interpreted.** `Reply-To` is not turned
  into a `Mailbox`, `Date` is not parsed into a timestamp: a re-render must keep
  the sender's bytes, and interpretation belongs to the caller.

## Tests

- Unit, integration, edge-case-matrix and security tests per function:
  empty input, headers-only, no body, CRLF/LF/CR, tab folding, 8-bit bodies and
  headers, duplicate and empty-valued unknown headers, invalid base64, truncated
  multipart, unknown transfer encoding, 1000 recipients, nesting/size bombs,
  `Content-ID` injection, concurrency (16 threads).
- Property tests (`proptest`): arbitrary `Message` → render → parse round-trip
  (preserved headers included), render→parse→render stability, header folding
  round-trip, RFC 2047 round-trip, `parse` never panics on arbitrary text *or*
  arbitrary bytes, base64/quoted-printable output bounded by input, charset
  decoding total, and — with `dkim` — the body hash against an independent
  canonicalizer for arbitrary bodies, sign→verify for arbitrary bodies, and
  tamper detection.
- Doctests on every public item; `#![deny(missing_docs)]`,
  `#![forbid(unsafe_code)]`.
- Per-rule limit tests (`tests/rfc_limits.rs`), one test per number a receiver
  relies on: the 78-character header line, the 998-octet body line with both
  sides of the boundary, the 75-character encoded-word that still decodes on its
  own, and quoted-printable lines within 76.
- Line coverage: **97.2 %** (`cargo llvm-cov --all-features --summary-only`; the
  `dkim` module itself 97.6 %). CI fails below 95 %.

### Fuzzing

```
cargo +nightly fuzz build parse       # CI builds this target
cargo +nightly fuzz run parse         # run it (seeds: fuzz/corpus/parse)
cargo +nightly fuzz run parse fuzz/artifacts/parse/<crash>   # reproduce
```

The target parses arbitrary bytes both as UTF-8 and lossily, rewrites `cid:`
references over arbitrary text, re-renders and re-parses whatever was accepted,
parses the resulting `DKIM-Signature` fields, and signs plus verifies with a
fixed key. Seed corpus: `simple.eml`, `multipart.eml` (nested mixed +
alternative + RFC 2231 filename), `folded.eml` (folding, Q encoding,
quoted-printable), `truncated.eml`, `headers.eml` (folded, duplicated, empty and
8-bit unknown headers), `related.eml` (inline part with `Content-ID`),
`dkim.eml` (RFC 8463 example). 171k executions in a 45-second run, no crashes.

## Versioning

`0.y.z`: a **minor** bump may break (Cargo's pre-1.0 rule), a **patch** bump
never does. `Error` and the payload enums are `#[non_exhaustive]`, so new
variants arrive without a breaking release. **MSRV: Rust 1.89**
(`rust-version` in `Cargo.toml`); it can rise in a minor release and stays put
within a patch line. Every release is recorded in
[CHANGELOG.md](CHANGELOG.md), which states the full policy.

## License

Apache-2.0 OR MIT.
