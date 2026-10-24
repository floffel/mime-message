//! Build and parse RFC 5322 / MIME messages — no SMTP, no I/O.
//!
//! ```no_run
//! use mime_message::{Attachment, Message};
//!
//! # fn main() -> Result<(), mime_message::Error> {
//! let raw = Message::builder()
//!     .from("Shop <shop@example.com>")?
//!     .to("kunde@example.com")?
//!     .subject("Ihre Rechnung")
//!     .body("Anbei die Rechnung.")
//!     .attachment(Attachment::new("rechnung.pdf", "application/pdf", b"%PDF-1.4".to_vec()))
//!     .build()?;
//!
//! let bytes = raw.render()?;
//! assert!(bytes.windows(2).any(|w| w == b"\r\n"));
//! # Ok(())
//! # }
//! ```
//!
//! The other half is [`Message::parse`]:
//!
//! ```
//! use mime_message::Message;
//!
//! let raw = concat!(
//!     "From: \"Shop\" <shop@example.com>\r\n",
//!     "To: kunde@example.com\r\n",
//!     "Subject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\r\n",
//!     "Content-Type: text/plain; charset=utf-8\r\n",
//!     "\r\n",
//!     "Hallo\r\n",
//! );
//! let message = Message::parse(raw)?;
//! assert_eq!(message.subject, "Grüße");
//! assert_eq!(message.body, "Hallo\r\n");
//! # Ok::<(), mime_message::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod charset;
pub mod error;
mod parse;
mod render;
pub mod rfc2047;
pub mod transfer;

pub use error::{Error, Result};
pub use parse::{parse, parse_with_limits, Limits};

/// A single mailbox (`Display Name <local@domain>` or `local@domain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Optional display name.
    pub name: Option<String>,
    /// The address as given.
    pub address: String,
}

impl Mailbox {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(Error::EmptyHeader("mailbox"));
        }
        if let (Some(start), Some(end)) = (raw.find('<'), raw.rfind('>')) {
            // Brackets in the wrong order (">...<") would make the slice panic.
            if end <= start + 1 {
                return Err(Error::InvalidMailbox(raw.to_string()));
            }
            let address = raw[start + 1..end].trim().to_string();
            if !address.contains('@') {
                return Err(Error::InvalidMailbox(raw.to_string()));
            }
            let name = raw[..start].trim().trim_matches('"').to_string();
            let name = if name.is_empty() { None } else { Some(name) };
            return Ok(Self { name, address });
        }
        if !raw.contains('@') {
            return Err(Error::InvalidMailbox(raw.to_string()));
        }
        Ok(Self {
            name: None,
            address: raw.to_string(),
        })
    }
}

/// One attachment with its raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// File name shown by the client.
    pub filename: String,
    /// MIME type, for example `application/pdf`.
    pub content_type: String,
    /// File contents.
    pub data: Vec<u8>,
}

impl Attachment {
    /// Creates an attachment.
    #[must_use]
    pub fn new(
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            filename: filename.into(),
            content_type: content_type.into(),
            data,
        }
    }
}

/// A message, either built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Envelope sender as it appears in `From:`.
    pub from: Mailbox,
    /// Recipients for `To:`.
    pub to: Vec<Mailbox>,
    /// Recipients for `Cc:`.
    pub cc: Vec<Mailbox>,
    /// Subject, may contain non-ASCII.
    pub subject: String,
    /// Plain text body.
    pub body: String,
    /// Optional `text/html` alternative, rendered as `multipart/alternative`.
    pub html_body: Option<String>,
    /// Optional `Date:` header, caller supplied to keep rendering deterministic.
    pub date: Option<String>,
    /// Optional `Message-ID:`.
    pub message_id: Option<String>,
    /// Attachments; presence switches the message to `multipart/mixed`.
    pub attachments: Vec<Attachment>,
}

/// Step-by-step builder for [`Message`].
#[derive(Debug, Default)]
pub struct MessageBuilder {
    from: Option<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    subject: String,
    body: String,
    html_body: Option<String>,
    date: Option<String>,
    message_id: Option<String>,
    attachments: Vec<Attachment>,
}

impl Message {
    /// Starts a builder.
    #[must_use]
    pub fn builder() -> MessageBuilder {
        MessageBuilder::default()
    }

    /// Renders the message as bytes with CRLF line endings.
    ///
    /// # Errors
    ///
    /// Fails on header injection, missing headers, or no recipients.
    pub fn render(&self) -> Result<Vec<u8>> {
        render::render(self)
    }

    /// Parses an RFC 5322 / MIME message with the default [`Limits`].
    ///
    /// ```
    /// use mime_message::Message;
    ///
    /// let message = Message::parse("From: a@example.com\r\nSubject: hi\r\n\r\nbody")?;
    /// assert_eq!(message.from.address, "a@example.com");
    /// assert_eq!(message.body, "body");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// See [`parse`] for the full list of typed failures.
    pub fn parse(raw: &str) -> Result<Self> {
        parse::parse(raw)
    }

    /// Parses a message with explicit [`Limits`].
    ///
    /// ```
    /// use mime_message::{Limits, Message};
    ///
    /// let mut limits = Limits::default();
    /// limits.max_parts = 1;
    /// let nested = "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n\
    ///     --b\r\n\r\nhi\r\n--b--\r\n";
    /// assert!(Message::parse_with_limits(nested, &limits).is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// See [`parse_with_limits`].
    pub fn parse_with_limits(raw: &str, limits: &Limits) -> Result<Self> {
        parse::parse_with_limits(raw, limits)
    }
}

impl MessageBuilder {
    /// Sets `From:`.
    ///
    /// # Errors
    ///
    /// Rejects malformed mailboxes.
    pub fn from(mut self, raw: &str) -> Result<Self> {
        self.from = Some(Mailbox::parse(raw)?);
        Ok(self)
    }

    /// Adds one `To:` recipient.
    ///
    /// # Errors
    ///
    /// Rejects malformed mailboxes.
    pub fn to(mut self, raw: &str) -> Result<Self> {
        self.to.push(Mailbox::parse(raw)?);
        Ok(self)
    }

    /// Adds one `Cc:` recipient.
    ///
    /// # Errors
    ///
    /// Rejects malformed mailboxes.
    pub fn cc(mut self, raw: &str) -> Result<Self> {
        self.cc.push(Mailbox::parse(raw)?);
        Ok(self)
    }

    /// Sets the subject.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Sets the plain text body.
    #[must_use]
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets an HTML alternative, rendered as `multipart/alternative`.
    #[must_use]
    pub fn html_body(mut self, html: impl Into<String>) -> Self {
        self.html_body = Some(html.into());
        self
    }

    /// Sets the `Date:` header (RFC 5322 format).
    #[must_use]
    pub fn date(mut self, date: impl Into<String>) -> Self {
        self.date = Some(date.into());
        self
    }

    /// Sets the `Message-ID:` header.
    #[must_use]
    pub fn message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Adds an attachment.
    #[must_use]
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Finishes the message.
    ///
    /// # Errors
    ///
    /// Fails when `From:` is missing or there is no recipient.
    pub fn build(self) -> Result<Message> {
        let from = self.from.ok_or(Error::EmptyHeader("From"))?;
        if self.to.is_empty() {
            return Err(Error::NoRecipients);
        }
        Ok(Message {
            from,
            to: self.to,
            cc: self.cc,
            subject: self.subject,
            body: self.body,
            html_body: self.html_body,
            date: self.date,
            message_id: self.message_id,
            attachments: self.attachments,
        })
    }
}
