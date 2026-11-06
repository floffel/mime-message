//! Incremental parsing from caller-supplied byte streams.
//!
//! This module does not open sockets or files. It accepts a `std::io::Read`
//! implementation or explicit chunks, enforces [`Limits::max_bytes`] before a
//! chunk is buffered, and delegates to the whole-message parser once EOF is
//! reached so depth, part-count and body limits stay exactly the same.

use std::io::Read;

use crate::error::{Error, Result};
use crate::parse::parse_with_limits;
use crate::{Limits, Message};

const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Reads an RFC 5322 / MIME message from `reader` with default [`Limits`].
///
/// ```
/// use std::io::Cursor;
/// use mime_message::stream;
///
/// let raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody";
/// let message = stream::parse_reader(Cursor::new(raw))?;
/// assert_eq!(message.subject, "hi");
/// assert_eq!(message.body, "body");
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// # Errors
///
/// Returns the same typed errors as [`parse`](crate::parse), plus
/// [`Error::InputTooLarge`] when
/// [`Limits::max_bytes`] is crossed and [`Error::InvalidUtf8`] or
/// [`Error::Read`] for stream-level failures.
pub fn parse_reader(reader: impl Read) -> Result<Message> {
    parse_reader_with_limits(reader, &Limits::default())
}

/// Reads an RFC 5322 / MIME message from `reader` with explicit [`Limits`].
///
/// ```
/// use std::io::Cursor;
/// use mime_message::{stream, Limits};
///
/// let mut limits = Limits::default();
/// limits.max_bytes = 64;
///
/// let raw = b"From: a@example.com\r\n\r\nhello";
/// assert!(stream::parse_reader_with_limits(Cursor::new(raw), &limits).is_ok());
///
/// let oversized = b"From: a@example.com\r\n\r\nhello over the configured streaming budget";
/// assert!(stream::parse_reader_with_limits(Cursor::new(oversized), &limits).is_err());
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// # Errors
///
/// As [`parse_reader`], using `limits` for every structural budget.
#[must_use = "the parsed message is the result"]
pub fn parse_reader_with_limits(mut reader: impl Read, limits: &Limits) -> Result<Message> {
    let mut parser = StreamParser::with_limits(*limits);
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    loop {
        let remaining = limits.max_bytes.saturating_sub(parser.bytes_received());
        let read_len = remaining.saturating_add(1).min(READ_BUFFER_BYTES);
        let read = reader
            .read(&mut buffer[..read_len])
            .map_err(|error| Error::read(&error))?;
        if read == 0 {
            break;
        }
        parser.push(&buffer[..read])?;
    }
    parser.finish()
}

/// Chunked parser for callers whose transport hands over bytes itself.
///
/// ```
/// use mime_message::stream::StreamParser;
///
/// let mut parser = StreamParser::new();
/// parser.push(b"From: a@example.com\r\n")?;
/// parser.push(b"Subject: hi\r\n\r\n")?;
/// parser.push(b"body")?;
/// let message = parser.finish()?;
/// assert_eq!(message.subject, "hi");
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// Chunks may split anywhere: between headers, inside CRLF, inside a
/// `multipart` boundary, and inside a body. The parser buffers accepted bytes
/// only after [`Limits::max_bytes`] has allowed them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StreamParser {
    limits: Limits,
    bytes: Vec<u8>,
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamParser {
    /// Creates a chunked parser with default [`Limits`].
    ///
    /// ```
    /// use mime_message::stream::StreamParser;
    ///
    /// let parser = StreamParser::new();
    /// assert_eq!(parser.bytes_received(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// Creates a chunked parser with explicit [`Limits`].
    ///
    /// ```
    /// use mime_message::{stream::StreamParser, Limits};
    ///
    /// let mut limits = Limits::default();
    /// limits.max_bytes = 1;
    /// let mut parser = StreamParser::with_limits(limits);
    /// assert!(parser.push(b"x").is_ok());
    /// assert_eq!(parser.bytes_received(), 1);
    /// assert!(parser.push(b"y").is_err());
    /// ```
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            bytes: Vec::new(),
        }
    }

    /// Appends the next transport chunk.
    ///
    /// ```
    /// use mime_message::stream::StreamParser;
    ///
    /// let mut parser = StreamParser::new();
    /// parser.push(b"From: a@example.com\r\n")?;
    /// parser.push(b"\r\nbody")?;
    /// assert_eq!(parser.finish()?.body, "body");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::InputTooLarge`] before
    /// appending a chunk that would push the raw byte count above
    /// [`Limits::max_bytes`].
    #[must_use = "the byte limit result must be checked before continuing"]
    pub fn push(&mut self, chunk: &[u8]) -> Result<()> {
        let Some(total) = self.bytes.len().checked_add(chunk.len()) else {
            return Err(Error::InputTooLarge {
                limit: self.limits.max_bytes,
                size: usize::MAX,
            });
        };
        if total > self.limits.max_bytes {
            return Err(Error::InputTooLarge {
                limit: self.limits.max_bytes,
                size: total,
            });
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    /// Finishes the stream and parses the accepted bytes.
    ///
    /// ```
    /// use mime_message::stream::StreamParser;
    ///
    /// let mut parser = StreamParser::new();
    /// parser.push(b"From: a@example.com\r\n\r\nbody")?;
    /// assert_eq!(parser.finish()?.body, "body");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUtf8`] when the accepted bytes are not UTF-8,
    /// and otherwise the same typed parse errors as [`parse`](crate::parse).
    #[must_use = "the parsed message is the result"]
    pub fn finish(self) -> Result<Message> {
        let raw = std::str::from_utf8(&self.bytes).map_err(|error| Error::InvalidUtf8 {
            offset: error.valid_up_to(),
        })?;
        parse_with_limits(raw, &self.limits)
    }

    /// Number of accepted raw message bytes.
    ///
    /// ```
    /// use mime_message::stream::StreamParser;
    ///
    /// let mut parser = StreamParser::new();
    /// parser.push(b"abc")?;
    /// assert_eq!(parser.bytes_received(), 3);
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn bytes_received(&self) -> usize {
        self.bytes.len()
    }
}
