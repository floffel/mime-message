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

### Added

- **`examples/compose_and_parse.rs`**, built and run in CI: composes an invoice mail
  (text, HTML alternative, inline logo with `Content-ID`, PDF attachment), asserts CRLF
  line endings, the 78-byte header limit, the render→parse round trip and `cid:`
  rewriting, and prints the rendered headers.

### Changed

- **Breaking (the next release is `0.4.0`): the payload types are `#[non_exhaustive]`.**
  `Attachment`, `dkim::SignParams` and `dkim::SignatureHeader` now say so explicitly, so a
  field can be added (`Content-Disposition`, an `x=` expiry, a `q=` query method) without a
  breaking release, and `dkim::Algorithm` / `dkim::Canonicalization` can gain a variant when
  the wire brings one. Building one of those structs with a struct literal — something no
  example or doc ever showed — stops compiling in a downstream crate; reading the public
  fields and the `new()` / setter constructors is unaffected. `Mailbox` stays
  literal-constructible on purpose: it is the complete RFC 5322 §3.4 shape, and the doc says
  so. These decisions are not prose any more: `tests/public_surface.rs` re-derives them from
  `src/` and fails when a public type omits the attribute without an exemption that names its
  reason, and when a public function loses its doctest. Mutation-checked both ways: dropping
  `#[non_exhaustive]` from `Attachment` fails the type gate, deleting one doc fence fails the
  doctest gate.

### Security

- **The advisory gate now audits every feature, not just the default set.** `deny.toml`
  gains a `[graph] all-features = true` block, because cargo-deny otherwise resolves
  default features only: `rsa` sits behind the non-default `dkim` feature and carries
  RUSTSEC-2023-0071, so the gate reported `advisories ok` for a dependency graph it never
  looked at. `unused-ignored-advisory = "deny"` makes that failure mode loud - an ignore
  that matches no crate is now an error - and a CI step fails the config when the
  `[graph]` block is removed. No API change; the documented ignore and its reasoning are
  unchanged.
- **The part budget is enforced while a `multipart` body is split, not after it.**
  `split_multipart` returned every part it found and `parse_entity` then built
  `Vec::with_capacity(raw_parts.len())` before the `max_parts` check could run, so a
  delimiter-dense body allocated one `Entity` slot per delimiter: a body just under the
  8 MiB body limit with 5-byte `--b\r\n` delimiters produced ~1.6 M slots (hundreds of
  MiB) for a budget of 1000 parts. The split now takes the remaining allowance as an
  argument and returns `Error::LimitExceeded` for `part count` on the first delimiter
  past it, before the part is stored, which also bounds the preallocation by
  `max_parts`. The allowance stays global across nested containers. Pinned by
  `part_limit_is_enforced_while_splitting_not_after` (200 000 parts, refused), the
  boundary pair `part_limit_pair_is_the_container_plus_its_children`,
  `part_limit_is_shared_across_nested_containers`, the split-level unit test and the
  proptest `part_limit_bounds_children`.

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

- **A text body is no longer allowed to break the 998-octet line limit, and non-ASCII
  bodies go out as quoted-printable instead of raw `8bit`.** RFC 5322 §2.1.1 says a line
  MUST be at most 998 characters, but the renderer copied the body into the message
  verbatim: a 2000-character line left the crate as a 2000-octet line, which a strict
  next hop refuses. The same path emitted a German body as raw UTF-8 under
  `Content-Transfer-Encoding: 8bit`, which is only legal when the next hop speaks
  8BITMIME (RFC 6152) or SMTPUTF8 (RFC 6532) — neither is something this crate can
  assume. `encode_text_body` now picks the encoding per text part: `8bit` stays for
  ASCII within the limit (the original bytes, untouched), everything else is
  quoted-printable (`transfer::encode_quoted_printable`, new: RFC 2045 §6.7, 7-bit
  clean, soft line breaks at 76 characters, trailing spaces and `=` escaped). Pinned
  by `tests/rfc_limits.rs`: `body_lines_never_exceed_the_998_octet_must`, the boundary
  pair `the_998_octet_boundary_is_inclusive` (998 stays `8bit`, 999 switches),
  `a_non_ascii_body_goes_out_seven_bit`, `every_text_part_chooses_its_own_encoding`,
  `the_encoder_escapes_what_the_wire_would_eat` and the proptest
  `quoted_printable_round_trips_any_text`; the DKIM body-hash property test now hashes
  the transmitted body, as RFC 6376 §3.4.4 requires.
- **The headers of a MIME part are folded like top-level headers.** `write_part_header`
  wrote `Content-Type: multipart/alternative; boundary="…"` and
  `Content-Disposition: …; filename="…"` raw, so a message with an HTML alternative
  carried an 83-byte header line, and a long filename another one — past the 78 bytes a
  reader may rely on (RFC 5322 §2.1.1), while the README promised folding "below 78
  characters". Part headers now go through the same `fold_header` and the same CR/LF
  rejection as the top of the message. Pinned by
  `no_header_line_exceeds_78_bytes_in_any_multipart_shape` over the plain, alternative,
  mixed and related shapes; it fails on the previous code with exactly those two lines.

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
