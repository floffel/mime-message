//! Errors raised while building a message.

use thiserror::Error;

/// Everything that prevents rendering a valid message.
#[derive(Debug, Error, PartialEq, Eq)]
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
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
