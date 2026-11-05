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

- **`cid::try_data_uri` validates a `Content-Type` before building a `data:` URI.** The
  fallible constructor parses the value as an RFC media type using the same path as
  `Content-Type` handling, rejects control bytes and unsafe URI/HTML delimiters, and
  percent-encodes parameters. `cid::data_uri` keeps its signature and now falls back to
  `application/octet-stream` for an invalid media type; `Message::rewrite_cid_references`
  uses the validating path and HTML-escapes replacements before inserting them into the
  caller's HTML.

- **`examples/compose_and_parse.rs`**, built and run in CI: composes an invoice mail
  (text, HTML alternative, inline logo with `Content-ID`, PDF attachment), asserts CRLF
  line endings, the 78-byte header limit, the render→parse round trip and `cid:`
  rewriting, and prints the rendered headers.

### Changed

- **Breaking (the next release is `0.4.0`): `Error::InvalidKey` carries a `KeyRejected`, not a
  `String`.** A caller that matched `Error::InvalidKey(message)` now receives
  `Error::InvalidKey(reason)` and can match the stage — `NotPem`, `UnsupportedPemLabel`,
  `NotBase64 { what }`, `WrongLength { what, expected, found }`,
  `BelowMinimumBits { bits, minimum }`, `MissingPublicKey`, `RevokedKey`,
  `UnsupportedKeyType`, `UnsupportedRecordVersion`, `TagWithoutEquals`, `EmptyTagName`,
  `DuplicateTag`, `InvalidRsaPublicKey`, `InvalidEd25519PublicKey` — instead of parsing a
  sentence. `KeyRejected` is `#[non_exhaustive]`, `Copy` and `Eq`, so `Error` stays
  comparable and a new reason is a minor release. `Error::source()` is still `None` for
  `InvalidKey`: the reason is the whole classification, and `InvalidKeyPem` remains the one
  variant with a cause chain.
- **Breaking (the next release is `0.4.0`): a structural parse failure now carries its location.**
  `Error::InvalidBase64` was a unit variant, and `MalformedHeader` / `InvalidContentType` carried text
  but no position, so an error inside a multipart body said *what* failed and never *where*: the
  caller could not identify the part, the line or the byte, and the boundary from the type — first bad
  byte versus just past the end — could not be tested. The three variants now carry
  `InvalidBase64 { part, offset }`, `MalformedHeader { part, line, text }` and
  `InvalidContentType { part, text }`, filled by `parse.rs`: `part` is the 1-based depth-first ordinal
  of the MIME entity, the message itself being 1 (so the first child of a top-level `multipart` is 2,
  read while the header block is parsed, not after the tree is built), `line` is the 1-based line
  inside that entity's header block, and `offset` is a byte offset in that part's body with its line
  breaks counted — the body length when only the length or the padding is wrong, which is the position
  just past the end. `0` means "no wire position": a name rejected by `Header::new` /
  `Header::from_wire` or by the renderer has neither a part nor a line, and
  `transfer::decode_base64` (public, unchanged signature) decodes a payload that belongs to no
  message. The offset is *mapped back* from the whitespace-free copy that the `base64` crate decodes,
  so it is a position a caller can look up in the message they hold. `text` stays truncated to 120
  bytes. Pinned by `tests/error_locations.rs` (`malformed_header_reports_the_part_and_the_line`,
  `the_reported_line_is_the_one_that_fails_not_the_block`,
  `a_continuation_line_without_a_field_names_its_line`, `invalid_base64_names_the_part_and_the_byte`,
  `invalid_base64_points_past_the_end_when_no_byte_is_wrong`, `the_body_of_the_message_itself_is_part_one`,
  `malformed_header_text_stays_truncated` — 120 bytes kept whole, 121 cut,
  `a_field_without_a_message_has_no_position`, `the_rendered_error_carries_the_location`), the
  transfer unit tests (a folded payload's offset counts the line break the decoder skipped; a length
  error points at `input.len()`) and the proptest `base64_errors_stay_inside_the_input`, which
  asserts every reported offset is a non-whitespace byte of the caller's input or its end. Callers
  that matched these three variants need the new shapes; that belongs to the `0.4.0` batch, not a
  patch.
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

- **`Error::InvalidMailbox` now escapes and bounds attacker-controlled mailbox text.** The
  variant rendered its payload verbatim, so CR, LF, ESC/ANSI sequences and any length of bytes
  reached logs as written, and the builder path kept the whole rejected address while the parser
  path capped it at 120 bytes. Both paths now build the error through `Error::invalid_mailbox`,
  the payload is truncated to 120 bytes at construction, and `Display` escapes it before rendering.
  Pinned by `tests/invalid_mailbox.rs`.
- **Mailbox addresses are validated again when a message is built or rendered.** A
  `Mailbox` built through the documented struct literal could carry `,`, `;` or `<`/`>`
  outside a quoted local part, so `render_mailbox` could turn one mailbox into several
  recipients. The shared validator now requires exactly one unquoted `@` and rejects
  address-list separators outside a quoted local part; `MessageBuilder::build` validates
  `From`, `To`, `Cc` and `Bcc`, and the renderer repeats the check before emitting a
  mailbox. Pinned by builder and render-path regression tests for the recipient-list
  injection.

- **`Error::InvalidKey` can no longer carry key material, by construction.** The variant was
  `InvalidKey(String)` with derived `Debug` and `Display`, and its call sites interpolated
  third-party parser text and an unsupported PEM label, so the documented promise "the message
  never contains key material" held only as long as every call site kept it. The payload is now
  `KeyRejected`: a closed enum whose fields are byte counts, bit counts and constants of this
  crate (`"Ed25519 seed"`, `"Ed25519 key"`, `"p="`), with no `String` to write a PEM body, a seed
  or a DNS `p=` value into. A tag-list defect is classified where the list is parsed (the
  signature path keeps its detailed message), and the parser text that used to be rendered no
  longer reaches the key message at all. Pinned by `tests/key_redaction.rs`: every reason is
  rendered and checked for `BEGIN`, `PRIVATE` and any run of 100+ base64 characters; key-shaped
  input is pushed through every PEM and DNS rejection and the whole source chain is checked end to
  end; and each limit the variant reports is pinned at its boundary — 31/32/33 bytes for the
  Ed25519 seed and for a `p=` key, and the RFC 8301 floor at exactly 1024 bits accepted
  (`tests/fixtures/rsa-1024.pem`, new) versus 512 bits rejected with `bits` and `minimum`. The
  fixture also pins that the boundary accepts a key rather than merely an error that looks right.

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
- **`ED25519 PRIVATE KEY` is no longer accepted as a key label.**
  Both private-key decoders this crate routes to (`ed25519-dalek` and `rsa`) require the
  standard PKCS#8 label `PRIVATE KEY`, so a block labelled `ED25519 PRIVATE KEY` could never
  load: the alternative matched the label and then failed in every decoder. It now falls
  through to the unsupported-label path, which is classified as
  `Error::InvalidKey(KeyRejected::UnsupportedPemLabel)` without probing a decoder or carrying
  a cause. `RSA PRIVATE KEY` (PKCS#1) and `PRIVATE KEY` (PKCS#8) are unchanged. Pinned by
  `tests/key_errors.rs` (the rejection has no source and the same body loads under
  `PRIVATE KEY`) and `tests/key_redaction.rs`.

- **RFC 2047 decoding keeps whitespace before an undecodable word.** The
  decoder dropped the gap between an encoded-word and a following token that
  merely started with `=?`, even when that token failed to decode and was
  copied verbatim. The gap is now consumed only after the second word decodes,
  so malformed input such as `=?UTF-8?Q?a?= =?UTF-8?X?b?=` renders as
  `a =?UTF-8?X?b?=` instead of losing the space.
- **A header fold can no longer be the last thing in a value.** `Header::from_wire`
  accepted `" a\r\n "` and `" a\r\n\t"` because a fold only had to start with
  whitespace, not continue with content; the renderer then wrote the trailing
  fold followed by its own CRLF, ending the header block and moving every later
  structural header into the body. The fold check now requires content after the
  continuation whitespace, rejects a value that starts with CRLF, and is shared
  with the renderer's guard so `Header::from_wire` and `render` agree. Pinned by
  the `from_wire` unit test and the header round-trip coverage in `tests/headers.rs`.
- **An unvalidated attachment `Content-Type` can no longer break out of a `data:` URI or
  an HTML attribute.** `Message::rewrite_cid_references` used to concatenate
  `attachment.content_type` directly into `data:<type>;base64,…`, so a value like
  `image/png" onerror="alert(1)` produced markup that escaped the quoted `src`
  attribute. The built-in rewrite now validates the media type before substituting,
  leaves the `cid:` reference unresolved on failure, and escapes replacement URIs.
  Pinned by focused tests for quotes, control characters, invalid parameters and safe
  percent-encoded parameters.
- **A malformed quoted-printable escape no longer deletes a lone CR or bare LF.**
  The decoder treated `=` followed by CR, and `=` followed by LF, as soft line
  breaks, so `decode_quoted_printable("a=\rb")` returned `ab`. Only `=` CRLF is a
  soft break now; `=` CR, `=` CR followed by another byte, and `=` LF are kept
  literal, matching the documented malformed-escape behaviour. Pinned by the
  quoted-printable boundary tests in `src/transfer.rs` and the property test
  `quoted_printable_malformed_line_endings_stay_literal`.

- **A `ControlCharacter` rejection says which field and which byte, not just a name.**
  The variant was `ControlCharacter(String)` and every construction site passed the header *name*
  while the documentation described a rejected *value*, so the message said "header X-A
  contains a control character" when `X-A` was fine and its value was not. Worse, the byte
  that failed the check was thrown away: NUL, VT, FF, DEL and a bare CR from a broken fold
  all produced the same payload, so no caller — and no test — could tell which one fired, or
  reproduce the rejection from the error. It is now
  `ControlCharacter { name, byte }`, filled through one internal constructor by all five
  checks (the `Header::new` / `Header::from_wire` value and fold checks, the parser's
  post-unfold check, the renderer's fold check and its `Content-ID` check), and it renders as
  `value of header "Subject" contains control byte 0x0b`. `byte` is the byte the check
  rejected; the `Content-ID` check reads characters rather than bytes and rejects `<`, `>`
  and whitespace as well, so for a non-ASCII character it reports the first byte of that
  character's UTF-8 encoding — the byte that identifies it in the input. Pinned by
  `tests/control_character.rs`: all eight common control bytes reported as themselves (NUL,
  BS, LF, VT, FF, CR, US, DEL), the boundary pairs of the rule (`0x1f` versus SP, tab versus
  VT, `0x7e` versus DEL, raw UTF-8 accepted), a CR that is not a fold reported as `0x0d`, the
  renderer's `Content-ID` path, and the rendered message; plus the proptest
  `header_new_reports_the_exact_byte`, which walks every byte below `0x80` and fails if the
  payload carries anything but the byte that was rejected, and the same invariant in the
  fuzz target (`fuzz/fuzz_targets/parse.rs`) over arbitrary input: the reported byte is in
  the message and is a forbidden one. A caller that matched
  `Error::ControlCharacter(_)` needs the new shape; that is part of the `0.4.0`
  batch, not a patch.

- **A PEM key that fails to decode now reports a typed cause instead of a sentence.**
  `SigningKey::from_pem` turned the PKCS#1 and PKCS#8 parser errors into
  `Error::InvalidKey(String)` via `format!`, so `Error::source()` was always `None` and
  the ASN.1/base64 cause was gone; the failed Ed25519 probe was discarded even earlier,
  on the way into the RSA fallback. Both now arrive as
  `Error::InvalidKeyPem(KeyParseError)` with the parser error as the `source()`, and
  `KeyParseError::Pkcs8` keeps *both* probe answers, so "an Ed25519 key with a corrupt
  field" and "a key of an algorithm this crate does not sign with" are distinguishable.
  `Error` keeps `PartialEq`/`Eq` because both inner errors are `Copy + Eq`. A caller that
  matched `Error::InvalidKey(_)` for a malformed PEM body needs `Error::InvalidKeyPem(_)`
  now; that is part of the `0.4.0` batch below, not a patch.

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
