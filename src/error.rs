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
    #[error("malformed header line: {0:?}")]
    MalformedHeader(String),
    /// A header value contains a forbidden control character (NUL, VT, FF, …).
    #[error("header {0:?} contains a control character")]
    ControlCharacter(String),
    /// A structural header that must appear once appears more than once.
    #[error("duplicate header: {0}")]
    DuplicateHeader(String),
    /// `Content-Type` is not `type/subtype`.
    #[error("invalid Content-Type: {0:?}")]
    InvalidContentType(String),
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
    #[error("invalid base64 payload")]
    InvalidBase64,
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
