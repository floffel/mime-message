//! Build and parse RFC 5322 / MIME messages — no SMTP, no I/O, no network.
//!
//! A parsed message keeps what the crate does not model: header fields it has
//! no typed field for are preserved byte for byte ([`Header`]), `Bcc:`
//! recipients land in [`Message::bcc`] instead of being dropped, and every MIME
//! part keeps its `Content-ID` so `cid:` references can be resolved locally
//! ([`cid`]). With the `dkim` feature the same message can be signed and
//! verified (`dkim`).
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
pub mod cid;
pub mod error;
mod header;
mod parse;
mod render;
pub mod rfc2047;
pub mod transfer;

#[cfg(feature = "dkim")]
pub mod dkim;

pub use error::{Error, Result};
pub use header::Header;
pub use parse::{parse, parse_with_limits, Limits};

/// `tchar` from RFC 5322 §3.2.2: the bytes a header name may consist of.
pub(crate) fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Header fields [`Message`] models itself; everything else is preserved.
pub(crate) const MODELLED_HEADERS: [&str; 10] = [
    "From",
    "To",
    "Cc",
    "Bcc",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

/// Shortens `text` to at most `max` bytes without splitting a character.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut cut = max;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

/// A single mailbox (`Display Name <local@domain>` or `local@domain`).
///
/// ```
/// use mime_message::Mailbox;
///
/// let mailbox = Mailbox {
///     name: Some("Shop".to_string()),
///     address: "shop@example.com".to_string(),
/// };
/// assert_eq!(mailbox.address, "shop@example.com");
/// ```
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
        // The `<` that starts the address must be outside a quoted display
        // name: `"Doe <Jr>" <a@b>` has two of them.
        if let Some(start) = parse::angle_open(raw) {
            let Some(end) = raw.rfind('>') else {
                return Err(Error::InvalidMailbox(raw.to_string()));
            };
            // Brackets in the wrong order (">...<") must not panic the slice.
            if end <= start + 1 {
                return Err(Error::InvalidMailbox(raw.to_string()));
            }
            let address = raw[start + 1..end].trim().to_string();
            parse::validate_address(&address)?;
            let name = parse::unquote(raw[..start].trim());
            if name.chars().any(char::is_control) {
                return Err(Error::InvalidMailbox(raw.to_string()));
            }
            let name = name.trim();
            return Ok(Self {
                name: if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                },
                address,
            });
        }
        parse::validate_address(raw)?;
        Ok(Self {
            name: None,
            address: raw.to_string(),
        })
    }
}

/// One attachment with its raw bytes.
///
/// ```rust
/// use mime_message::Attachment;
///
/// let attachment = Attachment::new("rechnung.pdf", "application/pdf", b"%PDF".to_vec());
/// assert_eq!(attachment.filename, "rechnung.pdf");
/// assert!(attachment.content_id.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// File name shown by the client.
    pub filename: String,
    /// MIME type, for example `application/pdf`.
    pub content_type: String,
    /// File contents.
    pub data: Vec<u8>,
    /// `Content-ID` of the part, without angle brackets, when it has one.
    ///
    /// This is what a `cid:` reference in the HTML body points at; see
    /// [`cid`] and [`Message::part_by_content_id`].
    pub content_id: Option<String>,
}

impl Attachment {
    /// Creates an attachment.
    ///
    /// ```
    /// # use mime_message::Attachment;
    /// let attachment = Attachment::new("a.txt", "text/plain", b"hi".to_vec());
    /// assert_eq!(attachment.content_type, "text/plain");
    /// ```
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
            content_id: None,
        }
    }

    /// Marks the part as inline content with a `Content-ID`.
    ///
    /// Angle brackets are optional and stripped, so `cid:logo` in the HTML
    /// resolves to the same part as `cid:<logo>`.
    ///
    /// ```
    /// use mime_message::Attachment;
    ///
    /// let logo = Attachment::new("logo.png", "image/png", vec![0x89, b'P'])
    ///     .with_content_id("<logo@example.com>");
    /// assert_eq!(logo.content_id.as_deref(), Some("logo@example.com"));
    /// ```
    #[must_use]
    pub fn with_content_id(mut self, id: impl AsRef<str>) -> Self {
        self.content_id = Some(cid::normalise(id.as_ref()).to_string());
        self
    }
}

/// A message, either built or parsed.
///
/// ```rust
/// use mime_message::Message;
///
/// let message = Message::parse("From: a@example.com\r\n\r\nbody")?;
/// assert_eq!(message.body, "body");
/// # Ok::<(), mime_message::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Envelope sender as it appears in `From:`.
    pub from: Mailbox,
    /// Recipients for `To:`.
    pub to: Vec<Mailbox>,
    /// Recipients for `Cc:`.
    pub cc: Vec<Mailbox>,
    /// Recipients for `Bcc:`.
    ///
    /// Parsed from a `Bcc:` header when one is present, and never rendered: a
    /// blind copy is defined by the recipient *not* seeing it, so the caller
    /// puts these addresses into the SMTP envelope instead of the message.
    pub bcc: Vec<Mailbox>,
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
    /// Header fields the crate does not model, in the order they arrived.
    headers: Vec<Header>,
}

/// Step-by-step builder for [`Message`].
///
/// ```
/// use mime_message::Message;
///
/// let message = Message::builder()
///     .from("a@example.com")?
///     .to("b@example.com")?
///     .subject("hi")
///     .build()?;
/// assert_eq!(message.to[0].address, "b@example.com");
/// # Ok::<(), mime_message::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct MessageBuilder {
    from: Option<Mailbox>,
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    bcc: Vec<Mailbox>,
    subject: String,
    body: String,
    html_body: Option<String>,
    date: Option<String>,
    message_id: Option<String>,
    attachments: Vec<Attachment>,
    headers: Vec<Header>,
}

impl Message {
    /// Starts a builder.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .build()?;
    /// assert_eq!(message.from.address, "a@example.com");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn builder() -> MessageBuilder {
        MessageBuilder::default()
    }

    /// Renders the message as bytes with CRLF line endings.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let raw = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("hi")
    ///     .build()?
    ///     .render()?;
    /// assert!(raw.ends_with(b"hi"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
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

    /// Every header field the crate does not model, in wire order.
    ///
    /// Names the crate turns into typed fields (`From`, `To`, `Cc`, `Bcc`,
    /// `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type`,
    /// `Content-Transfer-Encoding`) are not repeated here — read them from
    /// their field. Everything else (`Reply-To`, `In-Reply-To`,
    /// `List-Unsubscribe`, `Authentication-Results`, custom `X-` fields, …) is
    /// kept verbatim, duplicates included.
    ///
    /// ```rust
    /// use mime_message::Message;
    ///
    /// let raw = concat!(
    ///     "From: a@example.com\r\n",
    ///     "X-Spam-Score: 1.5\r\n",
    ///     "X-Spam-Score: 2.5\r\n",
    ///     "\r\n",
    ///     "hi",
    /// );
    /// let message = Message::parse(raw)?;
    /// let scores: Vec<_> = message
    ///     .headers()
    ///     .iter()
    ///     .filter(|header| header.is("X-Spam-Score"))
    ///     .map(|header| header.value())
    ///     .collect();
    /// assert_eq!(scores, ["1.5", "2.5"]);
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// The unfolded value of the first preserved header called `name`.
    ///
    /// The lookup is ASCII case-insensitive and covers only headers that are
    /// not modelled as typed fields; use `message.subject` and friends for
    /// those instead.
    ///
    /// ```rust
    /// use mime_message::Message;
    ///
    /// let message = Message::parse(
    ///     "From: a@example.com\r\nReply-To: replies@example.com\r\n\r\nhi",
    /// )?;
    /// assert_eq!(message.header("reply-to"), Some("replies@example.com"));
    /// assert_eq!(message.header("Subject"), None);
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.is(name))
            .map(Header::value)
    }

    /// Appends a header field; duplicates of the same name are kept.
    ///
    /// ```rust
    /// use mime_message::{Header, Message};
    ///
    /// let mut message = Message::parse("From: a@example.com\r\n\r\nhi")?;
    /// message.push_header(Header::new("X-Trace", "abc")?);
    /// let bytes = message.render()?;
    /// let raw = String::from_utf8_lossy(&bytes);
    /// assert!(raw.contains("X-Trace: abc\r\n"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    pub fn push_header(&mut self, header: Header) {
        self.headers.push(header);
    }

    /// Replaces every preserved header called like `header`, in place.
    ///
    /// When no such header exists it is appended. The first old entry keeps its
    /// position, later duplicates are dropped.
    ///
    /// ```rust
    /// use mime_message::{Header, Message};
    ///
    /// let mut message = Message::parse("From: a@example.com\r\nX-A: 1\r\n\r\nhi")?;
    /// message.set_header(Header::new("X-A", "2")?);
    /// assert_eq!(message.header("X-A"), Some("2"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    pub fn set_header(&mut self, header: Header) {
        let name = header.name().to_string();
        let Some(first) = self.headers.iter().position(|old| old.is(&name)) else {
            self.headers.push(header);
            return;
        };
        self.headers[first] = header;
        let mut index = first + 1;
        while index < self.headers.len() {
            if self.headers[index].is(&name) {
                self.headers.remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// Removes the first preserved header called `name` and returns it.
    ///
    /// ```rust
    /// use mime_message::Message;
    ///
    /// let mut message = Message::parse("From: a@example.com\r\nX-A: 1\r\n\r\nhi")?;
    /// assert!(message.remove_header("X-A").is_some());
    /// assert!(message.header("X-A").is_none());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    pub fn remove_header(&mut self, name: &str) -> Option<Header> {
        let index = self.headers.iter().position(|header| header.is(name))?;
        Some(self.headers.remove(index))
    }

    /// The part with this `Content-ID`, if any.
    ///
    /// `id` may be written as it appears in HTML (`cid:logo@example.com`,
    /// `cid:<logo@example.com>`) or as the bare id. Content-IDs are
    /// case-sensitive (RFC 2392), and no network access happens.
    ///
    /// ```rust
    /// use mime_message::{Attachment, Message};
    ///
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("hi")
    ///     .html_body("<img src=\"cid:logo\">")
    ///     .attachment(
    ///         Attachment::new("logo.png", "image/png", vec![0x89])
    ///             .with_content_id("logo"),
    ///     )
    ///     .build()?;
    /// let part = message.part_by_content_id("cid:logo").expect("inline part");
    /// assert_eq!(part.content_type, "image/png");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn part_by_content_id(&self, id: &str) -> Option<&Attachment> {
        let wanted = cid::normalise(id);
        self.inline_parts()
            .find(|part| part.content_id.as_deref() == Some(wanted))
    }

    /// Every attachment that carries a `Content-ID`.
    ///
    /// ```rust
    /// use mime_message::{Attachment, Message};
    ///
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("hi")
    ///     .attachment(Attachment::new("a.pdf", "application/pdf", vec![1]))
    ///     .attachment(Attachment::new("b.png", "image/png", vec![2]).with_content_id("b"))
    ///     .build()?;
    /// assert_eq!(message.inline_parts().count(), 1);
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    pub fn inline_parts(&self) -> impl Iterator<Item = &Attachment> + '_ {
        self.attachments
            .iter()
            .filter(|attachment| attachment.content_id.is_some())
    }

    /// Rewrites `cid:` references in `html` to `data:` URIs of the parts.
    ///
    /// The content is embedded as `data:<type>;base64,<bytes>`, so the result
    /// renders in any browser without network access. References without a
    /// matching part are left untouched — a broken image is better than a
    /// silently dropped one. For a URL-based rewrite (for example to an HTTP
    /// endpoint your webmail serves) use [`cid::rewrite`]
    /// with your own resolver.
    ///
    /// ```rust
    /// use mime_message::{Attachment, Message};
    ///
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("hi")
    ///     .html_body("<img src=\"cid:logo\"> <img src=\"cid:missing\">")
    ///     .attachment(
    ///         Attachment::new("logo.png", "image/png", b"\x89PNG".to_vec())
    ///             .with_content_id("logo"),
    ///     )
    ///     .build()?;
    /// let html = message.rewrite_cid_references("<img src=\"cid:logo\">");
    /// assert!(html.starts_with("<img src=\"data:image/png;base64,"));
    /// assert_eq!(
    ///     message.rewrite_cid_references("<img src=\"cid:missing\">"),
    ///     "<img src=\"cid:missing\">",
    /// );
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn rewrite_cid_references(&self, html: &str) -> String {
        cid::rewrite(html, |reference| {
            self.part_by_content_id(reference)
                .map(|part| cid::data_uri(&part.content_type, &part.data))
        })
    }
}

#[cfg(feature = "dkim")]
impl Message {
    /// Signs the message and returns the bytes to send, signature included.
    ///
    /// This is a thin wrapper around `dkim::sign`; see there for the
    /// parameters and the failure modes.
    ///
    /// ```rust
    /// use mime_message::dkim::{SignParams, SigningKey};
    /// use mime_message::Message;
    ///
    /// let key = SigningKey::from_ed25519_seed(&[1u8; 32]);
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("hi")
    ///     .build()?;
    /// let signed = message.sign(&key, &SignParams::new("example.com", "sel"))?;
    /// assert!(String::from_utf8_lossy(&signed).contains("a=ed25519-sha256"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Rendering errors, plus [`Error::InvalidSignature`] when the message has
    /// nothing signable.
    pub fn sign(
        &self,
        key: &crate::dkim::SigningKey,
        params: &crate::dkim::SignParams,
    ) -> Result<Vec<u8>> {
        crate::dkim::sign(self, key, params)
    }
}

impl MessageBuilder {
    /// Sets `From:`.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("Shop <shop@example.com>")?
    ///     .to("kunde@example.com")?
    ///     .build()?;
    /// assert_eq!(message.from.name.as_deref(), Some("Shop"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
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
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .to("c@example.com")?
    ///     .build()?;
    /// assert_eq!(message.to.len(), 2);
    /// # Ok::<(), mime_message::Error>(())
    /// ```
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
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .cc("c@example.com")?
    ///     .build()?;
    /// assert_eq!(message.cc[0].address, "c@example.com");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Rejects malformed mailboxes.
    pub fn cc(mut self, raw: &str) -> Result<Self> {
        self.cc.push(Mailbox::parse(raw)?);
        Ok(self)
    }

    /// Adds one `Bcc:` recipient.
    ///
    /// The address is parsed like `To:` but never rendered, so a blind copy
    /// stays blind; read [`Message::bcc`] to put it into the SMTP envelope.
    ///
    /// ```rust
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .bcc("secret@example.com")?
    ///     .build()?;
    /// assert_eq!(message.bcc[0].address, "secret@example.com");
    /// let bytes = message.render()?;
    /// let raw = String::from_utf8_lossy(&bytes);
    /// assert!(!raw.contains("secret@example.com"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Rejects malformed mailboxes.
    pub fn bcc(mut self, raw: &str) -> Result<Self> {
        self.bcc.push(Mailbox::parse(raw)?);
        Ok(self)
    }

    /// Appends a header field the crate does not model.
    ///
    /// ```rust
    /// use mime_message::{Header, Message};
    ///
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .header(Header::new("Reply-To", "replies@example.com")?)
    ///     .build()?;
    /// assert_eq!(message.header("reply-to"), Some("replies@example.com"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn header(mut self, header: Header) -> Self {
        self.headers.push(header);
        self
    }

    /// Sets the subject.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .subject("Grüße")
    ///     .build()?;
    /// assert_eq!(message.subject, "Grüße");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Sets the plain text body.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("Hallo")
    ///     .build()?;
    /// assert_eq!(message.body, "Hallo");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets an HTML alternative, rendered as `multipart/alternative`.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .body("Hallo")
    ///     .html_body("<p>Hallo</p>")
    ///     .build()?;
    /// assert_eq!(message.html_body.as_deref(), Some("<p>Hallo</p>"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn html_body(mut self, html: impl Into<String>) -> Self {
        self.html_body = Some(html.into());
        self
    }

    /// Sets the `Date:` header (RFC 5322 format).
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .date("Tue, 21 Oct 2026 10:00:00 +0000")
    ///     .build()?;
    /// assert!(message.date.is_some());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn date(mut self, date: impl Into<String>) -> Self {
        self.date = Some(date.into());
        self
    }

    /// Sets the `Message-ID:` header.
    ///
    /// ```
    /// # use mime_message::Message;
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .message_id("<abc@example.com>")
    ///     .build()?;
    /// assert_eq!(message.message_id.as_deref(), Some("<abc@example.com>"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = Some(id.into());
        self
    }

    /// Adds an attachment.
    ///
    /// ```
    /// # use mime_message::{Attachment, Message};
    /// let message = Message::builder()
    ///     .from("a@example.com")?
    ///     .to("b@example.com")?
    ///     .attachment(Attachment::new("a.txt", "text/plain", b"hi".to_vec()))
    ///     .build()?;
    /// assert_eq!(message.attachments[0].filename, "a.txt");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Finishes the message.
    ///
    /// ```rust
    /// use mime_message::{Error, Message};
    /// // A recipient is mandatory.
    /// assert_eq!(
    ///     Message::builder().from("a@example.com")?.build().unwrap_err(),
    ///     Error::NoRecipients
    /// );
    /// // A blind copy counts as a recipient …
    /// let bcc_only = Message::builder()
    ///     .from("a@example.com")?
    ///     .bcc("b@example.com")?
    ///     .build()?;
    /// assert!(bcc_only.to.is_empty());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Fails when `From:` is missing or there is neither a `To:` nor a `Bcc:`
    /// recipient.
    pub fn build(self) -> Result<Message> {
        let from = self.from.ok_or(Error::EmptyHeader("From"))?;
        if self.to.is_empty() && self.bcc.is_empty() {
            return Err(Error::NoRecipients);
        }
        Ok(Message {
            from,
            to: self.to,
            cc: self.cc,
            bcc: self.bcc,
            subject: self.subject,
            body: self.body,
            html_body: self.html_body,
            date: self.date,
            message_id: self.message_id,
            attachments: self.attachments,
            headers: self.headers,
        })
    }
}
