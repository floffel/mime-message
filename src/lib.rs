//! Build RFC 5322 / MIME messages as bytes — no SMTP, no I/O.
//!
//! ```
//! use mime_message::{Attachment, Message};
//!
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
//! # Ok::<(), mime_message::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
mod render;

pub use error::{Error, Result};

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

/// A message ready to be rendered.
#[derive(Debug, Clone)]
pub struct Message {
    /// Envelope sender as it appears in `From:`.
    pub from: Mailbox,
    /// Recipients for `To:`.
    pub to: Vec<Mailbox>,
    /// Subject, may contain non-ASCII.
    pub subject: String,
    /// Plain text body.
    pub body: String,
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
    subject: String,
    body: String,
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
            subject: self.subject,
            body: self.body,
            date: self.date,
            message_id: self.message_id,
            attachments: self.attachments,
        })
    }
}
