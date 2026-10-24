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
