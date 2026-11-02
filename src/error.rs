//! Errors raised while building, rendering or parsing a message.

use thiserror::Error;

/// Everything that prevents building, rendering or parsing a valid message.
///
/// ```
/// use mime_message::{parse, Error};
///
/// assert_eq!(parse("").unwrap_err(), Error::EmptyMessage);
/// ```
///
/// The enum is `#[non_exhaustive]`: match with a `_` arm so new checks can be
/// added without a breaking release.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A header value contains CR or LF — trying to inject headers.
    #[error("header {0:?} must not contain CR or LF")]
    HeaderInjection(&'static str),
    /// A required header is empty.
    #[error("header {0:?} must not be empty")]
    EmptyHeader(&'static str),
    /// The message has no recipient.
    #[error("message needs at least one recipient")]
    NoRecipients,
    /// A local part or domain is obviously malformed (no `@`).
    #[error("invalid mailbox: {0}")]
    InvalidMailbox(String),
    /// The input contains no header block at all.
    #[error("message has no headers")]
    EmptyMessage,
    /// A line in the header block is not `Name: value`.
    ///
    /// The payload says *where*: `part` is the 1-based ordinal of the MIME entity
    /// whose header block was being read, counted depth-first with the message
    /// itself as part 1, and `line` is the 1-based line inside that block. Both
    /// are 0 when the field never had a wire position — it was built through
    /// [`Header::new`](crate::Header::new) or
    /// `Header::from_wire`, or the renderer rejected a preserved name; `0` means
    /// "unknown", the convention a compiler diagnostic without a span uses.
    /// `text` is the offending line, truncated to 120 bytes.
    ///
    /// ```
    /// use mime_message::{parse, Error, Header};
    ///
    /// let raw = "From: a@example.com\r\nSubject: ok\r\nX A: 1\r\n\r\nx";
    /// let Error::MalformedHeader { part, line, .. } = parse(raw).unwrap_err() else {
    ///     panic!("a field name with a space is malformed");
    /// };
    /// assert_eq!((part, line), (1, 3));
    ///
    /// // A name rejected without a message has no position to report.
    /// let Error::MalformedHeader { part, line, .. } = Header::new("X A", "1").unwrap_err() else {
    ///     panic!("a field name with a space is malformed");
    /// };
    /// assert_eq!((part, line), (0, 0));
    /// ```
    #[error("malformed header at part {part}, line {line}: {text:?}")]
    MalformedHeader {
        /// 1-based depth-first entity ordinal, the message itself being 1; `0`
        /// when the field was never part of a parsed message.
        part: usize,
        /// 1-based line inside that entity's header block; `0` when there was no
        /// wire line.
        line: usize,
        /// The offending line, truncated to 120 bytes.
        text: String,
    },
    /// A header value contains a forbidden control character (NUL, VT, FF, …).
    #[error("header {0:?} contains a control character")]
    ControlCharacter(String),
    /// A structural header that must appear once appears more than once.
    #[error("duplicate header: {0}")]
    DuplicateHeader(String),
    /// `Content-Type` is not `type/subtype`.
    ///
    /// `part` names the entity whose header failed, in the same depth-first
    /// numbering as [`Error::MalformedHeader`], and `text` is the offending
    /// value, truncated to 120 bytes.
    ///
    /// ```
    /// use mime_message::{parse, Error};
    ///
    /// let raw = "From: a@example.com\r\nContent-Type: text\r\n\r\nx";
    /// let Error::InvalidContentType { part, text } = parse(raw).unwrap_err() else {
    ///     panic!("`text` is not a media type");
    /// };
    /// assert_eq!((part, text.as_str()), (1, "text"));
    /// ```
    #[error("invalid Content-Type (part {part}): {text:?}")]
    InvalidContentType {
        /// 1-based depth-first entity ordinal, the message itself being 1.
        part: usize,
        /// The offending `Content-Type` value, truncated to 120 bytes.
        text: String,
    },
    /// A `multipart/*` body has no `boundary` parameter.
    #[error("multipart message without a boundary parameter")]
    MissingBoundary,
    /// A `multipart/*` body ends without its closing delimiter.
    #[error("multipart body ends before its closing boundary")]
    UnterminatedMultipart,
    /// `Content-Transfer-Encoding` names an encoding we cannot decode.
    #[error("unsupported Content-Transfer-Encoding: {0}")]
    UnsupportedTransferEncoding(String),
    /// A base64 payload contains characters outside the alphabet.
    ///
    /// The payload says *where*: `part` names the MIME entity whose body failed,
    /// in the same depth-first numbering as [`Error::MalformedHeader`], and
    /// `offset` is the byte offset of the byte the decoder rejected, counted
    /// from the start of that part's body with its line breaks included. A
    /// payload that is only too short, or padded impossibly, has no wrong byte to
    /// point at; `offset` is then the length of the body — the position just past
    /// the end. A `part` of 0 means the payload was decoded on its own, through
    /// [`transfer::decode_base64`](crate::transfer::decode_base64), not as part
    /// of a parsed message.
    ///
    /// ```
    /// use mime_message::{parse, Error};
    ///
    /// let raw = concat!(
    ///     "From: a@example.com\r\n",
    ///     "Content-Transfer-Encoding: base64\r\n",
    ///     "\r\n",
    ///     "QUJD\r\nQUJ*\r\n",
    /// );
    /// let Error::InvalidBase64 { part, offset } = parse(raw).unwrap_err() else {
    ///     panic!("the body is not base64");
    /// };
    /// assert_eq!(part, 1); // the message's own body
    /// assert_eq!(offset, 9); // the '*' after the fold
    ///
    /// // A standalone payload belongs to no message, and a length error points
    /// // one past the end instead of at a byte.
    /// assert_eq!(
    ///     mime_message::transfer::decode_base64("S").unwrap_err(),
    ///     Error::InvalidBase64 { part: 0, offset: 1 }
    /// );
    /// ```
    #[error("invalid base64 payload (part {part}, offset {offset})")]
    InvalidBase64 {
        /// 1-based depth-first entity ordinal, the message itself being 1; `0`
        /// when the payload was decoded on its own.
        part: usize,
        /// Byte offset of the rejected byte in that part's body, line breaks
        /// included; the body length when only its length or padding is wrong.
        offset: usize,
    },
    /// An attachment filename could escape a download directory.
    #[error("unsafe attachment filename: {0:?}")]
    UnsafeFilename(String),
    /// A structural limit (nesting depth, part count, bytes) was exceeded.
    #[error("{what} exceeds the limit of {limit}")]
    LimitExceeded {
        /// Which limit was hit, for example `"nesting depth"`.
        what: &'static str,
        /// The configured maximum.
        limit: usize,
    },
    /// A DKIM private or public key could not be read.
    ///
    /// Covers PEM that is not a key, an unknown key type, a revoked (empty
    /// `p=`) DNS record, a key whose algorithm is unsupported, and keys below
    /// the RFC 8301 minimum of 1024 RSA bits.
    ///
    /// The message never contains key material, and that is a property of this
    /// type rather than of the call sites: the payload is [`KeyRejected`], a
    /// closed set of reasons whose fields are byte counts and constants of this
    /// crate. There is no `String` to interpolate a PEM body, a seed or a DNS
    /// `p=` value into, so `Display`, `Debug` and a `{:?}` in a panic all print
    /// the reason and nothing else.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    /// use mime_message::{Error, KeyRejected};
    ///
    /// let error = SigningKey::from_pem("; p=AA==").unwrap_err();
    /// assert_eq!(error, Error::InvalidKey(KeyRejected::NotPem));
    /// assert!(error.to_string().starts_with("invalid DKIM key: not a PEM block"));
    /// // Nothing of the rejected input is echoed back.
    /// assert!(!format!("{error} {error:?}").contains("p=AA=="));
    /// ```
    #[cfg(feature = "dkim")]
    #[error("invalid DKIM key: {0}")]
    InvalidKey(KeyRejected),

    /// A PEM private key does not decode as PKCS#1 or PKCS#8.
    ///
    /// The parser's own answer is kept as this variant's
    /// [`source`](std::error::Error::source), so the cause chain reaches the
    /// base64 and ASN.1 layer instead of stopping at a rendered string. This is
    /// the only variant of [`enum@Error`] whose `source()` is `Some`.
    #[cfg(feature = "dkim")]
    #[error("invalid DKIM key: {0}")]
    InvalidKeyPem(#[source] Box<KeyParseError>),
    /// A `DKIM-Signature` header field is malformed.
    ///
    /// Missing or duplicated tags, an unsupported algorithm or
    /// canonicalization, and unparseable base64 all land here.
    #[cfg(feature = "dkim")]
    #[error("invalid DKIM signature: {0}")]
    InvalidSignature(String),
    /// The message carries no `DKIM-Signature` header field.
    #[cfg(feature = "dkim")]
    #[error("message has no DKIM-Signature header field")]
    MissingSignature,
    /// No `DKIM-Signature` in the message was made with this key's algorithm.
    #[cfg(feature = "dkim")]
    #[error("no DKIM-Signature uses the algorithm of this key")]
    NoMatchingSignature,
    /// The body hash in the signature does not match the body.
    #[cfg(feature = "dkim")]
    #[error("DKIM body hash mismatch: the body was modified")]
    BodyHashMismatch,
    /// The signature does not verify against the header hash.
    #[cfg(feature = "dkim")]
    #[error("DKIM signature does not verify: a signed header was modified")]
    SignatureMismatch,
}

/// Why a DKIM key was rejected — the payload of [`Error::InvalidKey`].
///
/// This type exists so that the documented guarantee "the message never
/// contains key material" is enforced by the type and not by every call site.
/// A reason holds byte counts, `usize` bit counts, and `&'static str` constants
/// of this crate; it has no `String` field, so a PEM body, a seed or a DNS `p=`
/// value has nowhere to go. That also means the input never has to be scrubbed
/// on the way out: `Display`, `Debug` and the panic path print the same fixed
/// text.
///
/// What an operator still gets is the stage, which is the part that says what
/// to fix: not a PEM block, a PEM label this crate does not read, a payload
/// that is not base64, a decoded key of the wrong length, an RSA modulus under
/// the RFC 8301 floor, or a DNS record with a broken tag list, the wrong
/// version, no key, a revoked key, or an unknown key type.
///
/// ```
/// use mime_message::dkim::SigningKey;
/// use mime_message::{Error, KeyRejected};
///
/// // 44 base64 characters decode to 33 bytes: one past the 32-byte limit.
/// let error = SigningKey::from_ed25519_seed_base64(&"A".repeat(44)).unwrap_err();
/// assert_eq!(
///     error,
///     Error::InvalidKey(KeyRejected::WrongLength {
///         what: "Ed25519 seed",
///         expected: 32,
///         found: 33,
///     })
/// );
/// // The reason is fixed text plus the counts: nothing of the input.
/// assert_eq!(
///     error.to_string(),
///     "invalid DKIM key: Ed25519 seed must be 32 bytes, got 33"
/// );
/// ```
///
/// `#[non_exhaustive]`: a key format this crate learns to read can add a
/// reason, which is a minor release. Match with a `_` arm.
#[cfg(feature = "dkim")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRejected {
    /// The text contains no `-----BEGIN …-----` line.
    NotPem,
    /// The PEM label is not one this crate reads (`RSA PRIVATE KEY`,
    /// `PRIVATE KEY`, `ED25519 PRIVATE KEY`).
    ///
    /// The label itself is not repeated: it is caller text, and the message
    /// must not echo caller bytes.
    UnsupportedPemLabel,
    /// A key payload is not base64.
    NotBase64 {
        /// Which payload, as a constant of this crate (`"Ed25519 seed"`,
        /// `"p="`).
        what: &'static str,
    },
    /// A decoded key payload has the wrong length.
    WrongLength {
        /// Which key, as a constant of this crate (`"Ed25519 seed"`,
        /// `"Ed25519 key"`).
        what: &'static str,
        /// The length the format requires, in bytes.
        expected: usize,
        /// The length that was decoded, in bytes.
        found: usize,
    },
    /// An RSA modulus is below the RFC 8301 §3.2 floor of 1024 bits.
    BelowMinimumBits {
        /// The modulus size that was read, in bits.
        bits: usize,
        /// The floor this crate enforces, in bits.
        minimum: usize,
    },
    /// A DNS key record has a tag without `=`; it is not a `tag=value` list.
    TagWithoutEquals,
    /// A DNS key record has a tag with an empty name, for example `=x`.
    EmptyTagName,
    /// A DNS key record repeats a tag; RFC 6376 §3.6.1 allows each once.
    DuplicateTag,
    /// The `v=` tag is neither absent nor `DKIM1`.
    ///
    /// The tag value is not repeated: it is caller text.
    UnsupportedRecordVersion,
    /// The record has no `p=` tag at all.
    MissingPublicKey,
    /// The `p=` tag is present but empty — RFC 6376 §3.6.1 revokes the key,
    /// so every signature made with it must be treated as unverifiable.
    RevokedKey,
    /// The `k=` tag names a key type this crate does not verify; `rsa` and
    /// `ed25519` are the ones it does.
    ///
    /// The tag value is not repeated: it is caller text.
    UnsupportedKeyType,
    /// The `p=` payload is not an RSA `SubjectPublicKeyInfo` document.
    ///
    /// The parser's own words are not kept — a third-party `Display` is not a
    /// place to trust with a guarantee about key material.
    InvalidRsaPublicKey,
    /// The `p=` payload is not a valid Ed25519 curve point.
    InvalidEd25519PublicKey,
}

#[cfg(feature = "dkim")]
impl std::fmt::Display for KeyRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPem => write!(formatter, "not a PEM block (no label line)"),
            Self::UnsupportedPemLabel => write!(
                formatter,
                "unsupported PEM label (expected an RSA private key block)"
            ),
            Self::NotBase64 { what } => write!(formatter, "{what} is not base64"),
            Self::WrongLength {
                what,
                expected,
                found,
            } => write!(formatter, "{what} must be {expected} bytes, got {found}"),
            Self::BelowMinimumBits { bits, minimum } => write!(
                formatter,
                "RSA key is {bits} bits, RFC 8301 requires at least {minimum}"
            ),
            Self::TagWithoutEquals => write!(formatter, "DNS record has a tag without '='"),
            Self::EmptyTagName => write!(formatter, "DNS record has an empty tag name"),
            Self::DuplicateTag => write!(formatter, "DNS record repeats a tag"),
            Self::UnsupportedRecordVersion => {
                write!(formatter, "unsupported key record version (expected DKIM1)")
            }
            Self::MissingPublicKey => write!(formatter, "DNS record has no p= tag"),
            Self::RevokedKey => write!(formatter, "DNS record has a revoked key (p=)"),
            Self::UnsupportedKeyType => write!(
                formatter,
                "unsupported key type in the k= tag (expected rsa or ed25519)"
            ),
            Self::InvalidRsaPublicKey => write!(formatter, "not an RSA public key"),
            Self::InvalidEd25519PublicKey => write!(formatter, "not an Ed25519 public key"),
        }
    }
}

impl Error {
    /// A rejected field name from a call that had no wire position.
    ///
    /// [`Header::new`](crate::Header::new), `Header::from_wire` and the renderer
    /// spot a bad name without a header block around it, so both location fields
    /// of [`Error::MalformedHeader`] keep their "unknown" value, 0.
    pub(crate) fn malformed_name(name: &str) -> Self {
        Self::MalformedHeader {
            part: 0,
            line: 0,
            text: crate::truncate(name, 120),
        }
    }
}

/// The PKCS#1 or PKCS#8 parser error behind [`Error::InvalidKeyPem`].
///
/// `pkcs1` and `pkcs8` report *why* a PEM body did not decode (base64 that is
/// not base64, an ASN.1 field out of range, a version byte that cannot be
/// read), and that answer is what tells an operator whether the file was
/// truncated, is encrypted, or belongs to another algorithm. Rendering it into a
/// `String` threw the classification away; this type keeps it, and both inner
/// errors are `Copy + Eq`, so [`enum@Error`] stays comparable.
///
/// `#[non_exhaustive]`: a future key format adds a variant, which is a minor
/// release.
///
/// ```
/// use mime_message::dkim::SigningKey;
/// use mime_message::{Error, KeyParseError};
///
/// let pem = "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n-----END RSA PRIVATE KEY-----\n";
/// let error = SigningKey::from_pem(pem).unwrap_err();
/// let Error::InvalidKeyPem(cause) = error else {
///     panic!("a malformed PKCS#1 body must be a typed cause");
/// };
/// assert!(matches!(*cause, KeyParseError::Pkcs1(_)));
/// assert!(std::error::Error::source(&cause).is_some());
/// ```
#[cfg(feature = "dkim")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyParseError {
    /// A `RSA PRIVATE KEY` block did not decode as PKCS#1 (RFC 8017 A.1).
    Pkcs1(rsa::pkcs1::Error),
    /// A `PRIVATE KEY` block decoded as neither Ed25519 nor RSA PKCS#8.
    ///
    /// Both probes failed and both answers are kept: `ed25519` is what the
    /// Ed25519 attempt reported, `rsa` what the RSA fallback reported. Keeping
    /// the first one separates "an Ed25519 key with a corrupt field" from "a key
    /// of an algorithm this crate does not sign with".
    Pkcs8 {
        /// What decoding the block as an Ed25519 key reported.
        ed25519: rsa::pkcs8::Error,
        /// What decoding the same block as an RSA key reported.
        rsa: rsa::pkcs8::Error,
    },
}

#[cfg(feature = "dkim")]
impl std::fmt::Display for KeyParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs1(error) => write!(formatter, "PKCS#1: {error}"),
            Self::Pkcs8 { ed25519, rsa } => write!(
                formatter,
                "PKCS#8 decodes as neither Ed25519 ({ed25519}) nor RSA ({rsa})"
            ),
        }
    }
}

#[cfg(feature = "dkim")]
impl std::error::Error for KeyParseError {
    /// The RSA answer is the one that decides: a `PRIVATE KEY` block that gets
    /// here is neither algorithm, and the RSA decode is what the caller has to
    /// fail on. The Ed25519 answer stays readable through `Display` and by
    /// matching [`KeyParseError::Pkcs8`] directly.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pkcs1(error) => Some(error),
            Self::Pkcs8 { rsa, .. } => Some(rsa),
        }
    }
}

/// Convenience alias.
///
/// ```
/// use mime_message::{parse, Result};
///
/// fn subject_of(raw: &str) -> Result<String> {
///     Ok(parse(raw)?.subject)
/// }
/// assert_eq!(subject_of("From: a@example.com\r\nSubject: hi\r\n\r\nx")?, "hi");
/// # Ok::<(), mime_message::Error>(())
/// ```
pub type Result<T> = std::result::Result<T, Error>;
