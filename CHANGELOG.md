# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in
[Versioning](#versioning) below.

## Versioning

The crate is pre-1.0 (`0.y.z`), so Cargo's compatibility rule for `0.y` applies:
**a minor bump may break, a patch bump never does.** Concretely:

- **Patch (`0.3.3` -> `0.3.4`)** — bug fixes, security fixes, decoding fixes,
  documentation, and dependency updates that keep every public signature. A fix
  may change the *result* (a label that used to fail now decodes, a limit that
  rejected valid mail now accepts it), because the previous behaviour was wrong;
  it may not change the *shape* of the API.
- **Minor (`0.3.4` -> `0.4.0`)** — new public items, new typed fields on
  `#[non_exhaustive]` types, new error variants, and any changed or removed
  signature. Purely additive releases ship as minors too: pre-1.0, a reader has
  to assume a new minor can move.
- **MSRV** (`rust-version = "1.89"`) may rise in a **minor** release and only
  there; a patch release keeps the MSRV the previous patch declared. It is
  recorded in `Cargo.toml` and stated in the README.
- **Exhaustive matches are a breaking change.** `Error` and the payload enums are
  `#[non_exhaustive]`, so a new variant is a minor. Public *fields* are not
  exempt either: adding a field to a struct callers build with a struct literal
  breaks them, which is why new optional data arrives on a new type or accessor.
- **Yanking** is reserved for a release that is unsound or unusable; a wrong
  version is superseded by the next patch, never rewritten.

Every release gets a section here, committed together with the version bump in
`Cargo.toml`; the tag is `v<version>`. CI fails when a tag carries a version with
no section here, and the release workflow refuses to publish when the tag and the
manifest disagree.

## [Unreleased]

### Security

- **PEM key input is bounded at 64 KiB.** `SigningKey::from_pem` and
  `VerifyingKey::from_public_key_pem` handed the caller's whole string to the
  PEM/DER decoders, and an RSA key becomes a big-integer allocation proportional
  to its size, so an oversized blob cost CPU and memory in proportion to whatever
  was passed in. Both entry points now compare the byte length against
  `MAX_PEM_BYTES` (64 KiB — the largest key anyone deploys, 16384-bit RSA, is
  about 7 KiB in PEM form) before any decode and return
  `Error::LimitExceeded`. Pinned by
  `pem_input_is_bounded_before_any_decoder_runs`: exactly 64 KiB still parses,
  64 KiB + 1 is refused, and the error carries no key material.

### Fixed

- **DKIM body canonicalization no longer allocates per line.** `canonicalize_body`
  built a `Vec` of line slices and a second `Vec` per line before joining them,
  so a newline-dense body could amplify each input byte into tens of bytes of
  allocation (a body near the parser's 8 MiB limit could reach hundreds of
  MiB). It now makes two linear passes into one output buffer: the first finds the
  end of the last non-empty line (the trailing empties RFC 6376 §3.4.4 drops),
  the second writes the canonical lines straight into `out`, and `l=` stops the
  second pass early because it only keeps a prefix. Output stays bounded by
  `2 x input + 2`. Pinned by `a_line_per_byte_body_does_not_expand` (1 MiB of bare
  newlines, 256 Ki one-byte lines) plus proptests for the CRLF-only shape, the
  size bound, idempotence and `l=` prefix behaviour.

## [0.3.4] - 2026-10-27

### Fixed

- `max_depth` counts `multipart` *containers*, not entities. The check ran on
  every entity before the media type was known and used `depth >= max_depth`, so
  `max_depth = 0` rejected **every** message — including the non-multipart bodies
  the limit was never meant to protect — and a leaf part sitting at the limit's
  depth was refused for being a leaf. The limit now applies to a `multipart/*`
  entity only, with `depth > max_depth`: a flat body never meets it, and
  `max_depth = 0` still parses a flat message while refusing nesting.

## [0.3.3] - 2026-10-26

### Fixed

- Charset labels resolve through the WHATWG encoding registry (`encoding_rs`)
  instead of a closed list: every label the registry knows decodes — UTF-16
  LE/BE, ISO-8859-1 … -16, Windows-1251/1252, KOI8-R/U, Shift_JIS, GBK/GB18030,
  Big5, EUC-JP/KR — plus the spellings real mail uses that the registry omits
  (`utf16`, `utf16be`, `latin9`). US-ASCII and ISO-8859-1 decode as Windows-1252
  the way mail clients do; unknown and empty labels fall back to UTF-8 with
  replacement characters instead of failing the parse.

### Changed

- New dependency: `encoding_rs`. No public signature changed (`charset::decode`
  keeps its shape), so this is a patch.

## [0.3.2] - 2026-10-25

### Changed

- `base64` 0.22 -> 0.23. No API change.

## [0.3.1] - 2026-10-25

### Fixed

- `cargo doc --no-deps` (the CI gate, i.e. default features) failed on a broken
  intra-doc link: the crate-level docs linked to the feature-gated `dkim` module.
  The reference is plain text now; docs.rs builds with `all-features`
  (`[package.metadata.docs.rs]`), so the module stays documented there.

### Documentation

- RUSTSEC-2023-0071 (`rsa` 0.9: PKCS#1 v1.5 padding is not constant time, which
  matters for a *decryption* oracle) is recorded with its reasoning in
  `deny.toml` and stated in the README instead of being hidden. This crate never
  decrypts — DKIM signs with a caller-supplied key and verifies with public
  keys — so the affected path is unreachable.

## [0.3.0] - 2026-10-25

### Added

- **Unknown headers are preserved.** Every field the crate does not model is kept
  in wire order with its original name casing, spacing and folding, and
  re-rendered byte for byte: `Message::headers()`, `Message::header(name)`,
  `Header` (`new`, `from_wire`, `name`, `value`, `raw_value`, `is`). Duplicates
  stay separate entries; a preserved header that would duplicate a modelled one is
  rejected with `Error::DuplicateHeader`.
- **Inline `cid:` parts.** `Attachment::content_id`, `Message::part_by_content_id`,
  `Message::rewrite_cid_references` and the `cid` module (`normalise`, `data_uri`,
  `rewrite`). Lookups strip the `cid:` scheme and angle brackets, comparison is
  case-sensitive (RFC 2392), unresolved references are left untouched, and nothing
  is ever fetched.
- **DKIM behind the `dkim` feature.** RFC 6376 `rsa-sha256` and RFC 8463
  `ed25519-sha256`, `simple`/`relaxed` canonicalization for header and body,
  signing and verification: `SigningKey`, `VerifyingKey`, `SignParams`,
  `SignatureHeader`, `sign`, `verify`, `signatures`, `Algorithm`,
  `Canonicalization`. Signing is deterministic (the timestamp is a parameter);
  verification compares `bh=` in constant time, honours `l=`, and selects header
  instances bottom-up per RFC 6376 §5.4.2. No DNS, no key cache, no clock.
- Tests: RFC 8463 Appendix A.3 verifies for both signatures and its Ed25519
  signature is reproduced byte for byte from the published seed; `simple/simple`
  is pinned by hand-written canonical inputs (RFC 6376 §3.4.1). RFC 6376
  Appendix A.2 is documented as *not* used, with the reason.

## [0.2.0] - 2026-10-24

First published release (0.1.0 was never released).

### Added

- `Message::builder()` -> `render()`: CRLF line endings, header folding below 78
  characters, RFC 2047 encoding for non-ASCII subjects and display names, base64
  attachments, `multipart/alternative` when an HTML body is supplied,
  `multipart/related` when every attachment carries a `Content-ID`, and
  rejection of CR/LF in subject, filename and `Content-ID` (header injection).
- `Message::parse()` for RFC 5322 + MIME: CRLF/LF/bare-CR, folded and commented
  headers, groups, duplicate recipient headers joined, duplicate structural
  headers rejected, RFC 2047 `B`/`Q` decoding, `base64`/`quoted-printable`/
  `7bit`/`8bit`/`binary`, `multipart/mixed|alternative|related` nested
  arbitrarily, `Content-Type` parameters including RFC 2231 extended and
  continued ones, `Content-Disposition` filenames with path traversal rejected.
- `Bcc:` is parsed into `Message::bcc` and never rendered, so a blind copy stays
  blind.
- A typed `Error` for every malicious input instead of a panic or an OOM, plus
  `Limits` / `parse_with_limits()` for tighter budgets.
- Tests: edge-case matrix, security boundaries, `proptest` properties
  (render -> parse round-trip, stability, no panic on arbitrary bytes), a
  `cargo-fuzz` `parse` target with a seed corpus, doctests on every public item,
  and a 95 % line-coverage floor in CI.
