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
    /// A header field's value contains a byte the field cannot carry.
    ///
    /// `name` names the field, in the casing it arrived with, and `byte` is the
    /// byte the check rejected, so the answer is not thrown away: a NUL, a VT, a
    /// DEL and a non-ASCII control character are different bugs, and a test can
    /// assert which one fired. No byte is ever a placeholder here — every
    /// rejection has a real byte behind it.
    ///
    /// ```
    /// use mime_message::{parse, Error};
    ///
    /// let raw = "From: a@example.com\r\nSubject: a\u{0}b\r\n\r\nx";
    /// let Error::ControlCharacter { name, byte } = parse(raw).unwrap_err() else {
    ///     panic!("a NUL in a header value is rejected");
    /// };
    /// assert_eq!(name, "Subject");
    /// assert_eq!(byte, 0x00);
    /// assert_eq!(
    ///     Error::ControlCharacter { name, byte }.to_string(),
    ///     r#"value of header "Subject" contains control byte 0x00"#
    /// );
    ///
    /// // A different byte is a different answer: a vertical tab, not a NUL.
    /// let raw = "From: a@example.com\r\nSubject: a\u{b}b\r\n\r\nx";
    /// let Error::ControlCharacter { byte, .. } = parse(raw).unwrap_err() else {
    ///     panic!("a VT in a header value is rejected");
    /// };
    /// assert_eq!(byte, 0x0b);
    ///
    /// // The same field with a plain tab is accepted: tab is the one control
    /// // character a value may carry.
    /// assert!(parse("From: a@example.com\r\nSubject: a\tb\r\n\r\nx").is_ok());
    /// ```
    #[error("value of header {name:?} contains control byte 0x{byte:02x}")]
    ControlCharacter {
        /// The field whose value was rejected, with its original casing.
        name: String,
        /// The byte the check rejected.
        ///
        /// The byte-wise checks (`Header::new`, `Header::from_wire`, the parser
        /// and the renderer) report the offending byte itself: below `0x20`
        /// without tab, or `0x7f`. The `Content-ID` check reads *characters* and
        /// also rejects `<`, `>` and whitespace, which are not control bytes but
        /// cannot be re-rendered safely there; for a non-ASCII character it
        /// reports the first byte of that character's UTF-8 encoding, because a
        /// `char` above `0x7f` has no single byte of its own.
        byte: u8,
    },
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
    /// the RFC 8301 minimum of 1024 RSA bits. The message never contains key
    /// material.
    #[cfg(feature = "dkim")]
    #[error("invalid DKIM key: {0}")]
    InvalidKey(String),

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

    /// A control byte rejected in the value of `name`.
    ///
    /// One constructor for every place that rejects a control byte in a value —
    /// [`Header::new`](crate::Header::new),
    /// [`Header::from_wire`](crate::Header::from_wire), the parser, the
    /// renderer's fold check and its `Content-ID` check — so the payload is
    /// filled the same way everywhere and the name is converted once.
    pub(crate) fn control_value(name: &str, byte: u8) -> Self {
        Self::ControlCharacter {
            name: name.to_string(),
            byte,
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
