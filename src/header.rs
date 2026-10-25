//! Header fields that [`Message`](crate::Message) does not model itself.
//!
//! Everything the parser does not turn into a typed field (`From`, `To`,
//! `Subject`, …) is kept as a [`Header`] in the order it arrived, with the
//! original name casing, spacing and folding. Re-rendering such a message
//! reproduces those fields byte for byte, so a parsed mail can be forwarded
//! without losing `Reply-To`, `List-Unsubscribe`, `Authentication-Results` or
//! any other field the crate has no opinion about.

use crate::error::{Error, Result};

/// One header field, as it arrived on the wire.
///
/// The value is kept twice: [`Header::value`] is the unfolded, trimmed text a
/// caller wants to read, and [`Header::raw_value`] is the exact text after the
/// colon (line endings normalised to CRLF) that the renderer writes back out.
///
/// ```
/// use mime_message::Header;
///
/// let header = Header::new("List-Unsubscribe", "<mailto:unsub@example.com>")?;
/// assert_eq!(header.name(), "List-Unsubscribe");
/// assert_eq!(header.value(), "<mailto:unsub@example.com>");
/// assert_eq!(header.raw_value(), " <mailto:unsub@example.com>");
/// # Ok::<(), mime_message::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Header {
    /// Field name with its original casing.
    name: String,
    /// Everything after the colon: leading space, value, folds — verbatim.
    raw_value: String,
    /// `raw_value` unfolded and trimmed.
    value: String,
}

impl Header {
    /// Creates a header field from a name and an unfolded value.
    ///
    /// The value is trimmed; empty values are allowed (`X-Empty:` is a valid
    /// header). Line breaks are rejected: a header cannot smuggle a second one.
    ///
    /// ```
    /// use mime_message::Header;
    ///
    /// let header = Header::new("X-Report-Abuse", "https://example.com/report")?;
    /// assert_eq!(header.value(), "https://example.com/report");
    /// // A folded value is rejected, not folded for you.
    /// assert!(Header::new("X-Bad", "a\r\nBcc: evil@example.com").is_err());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MalformedHeader`] when the name is empty or is not a run of
    /// `tchar`s (RFC 5322 §3.6.8), and [`Error::ControlCharacter`] when the
    /// value contains CR, LF, NUL or any other control character except a tab.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let name = name.into();
        check_name(&name)?;
        let value = value.into();
        check_value(&name, &value)?;
        let trimmed = value.trim();
        let raw_value = if trimmed.is_empty() {
            String::new()
        } else {
            format!(" {trimmed}")
        };
        Ok(Self {
            name,
            raw_value,
            value: trimmed.to_string(),
        })
    }

    /// Builds a header from bytes that came off the wire.
    ///
    /// Unlike [`Header::new`], folded values (CRLF followed by a space or tab)
    /// are accepted and preserved.
    ///
    /// ```
    /// use mime_message::Header;
    ///
    /// let header = Header::from_wire("X-Trace", " one\r\n\ttwo")?;
    /// assert_eq!(header.value(), "one two");
    /// assert_eq!(header.raw_value(), " one\r\n\ttwo");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Rejects a malformed name, a bare CR or LF, a fold that does not start
    /// with whitespace, and control characters other than tab.
    pub fn from_wire(name: impl Into<String>, raw_value: impl Into<String>) -> Result<Self> {
        let name = name.into();
        check_name(&name)?;
        let raw_value = raw_value.into();
        check_folded_value(&name, &raw_value)?;
        Ok(Self {
            value: unfold(&raw_value),
            name,
            raw_value,
        })
    }

    /// The field name, with the casing it arrived with.
    ///
    /// ```
    /// # use mime_message::Header;
    /// let header = Header::new("x-lower", "1")?;
    /// assert_eq!(header.name(), "x-lower");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The unfolded, trimmed value.
    ///
    /// Folded continuation lines are joined with a single space, which is how
    /// RFC 5322 unfolding reads to a human. No RFC 2047 decoding is applied:
    /// unknown headers are returned as the sender wrote them.
    ///
    /// ```
    /// # use mime_message::Header;
    /// let header = Header::from_wire("Subject", " a\r\n b")?;
    /// assert_eq!(header.value(), "a b");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The exact text after the colon, including the leading space and folds.
    ///
    /// Line endings are normalised to CRLF; everything else is untouched, which
    /// is what makes a re-render byte-identical.
    ///
    /// ```
    /// # use mime_message::Header;
    /// let header = Header::from_wire("X-A", "  a")?;
    /// assert_eq!(header.raw_value(), "  a");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn raw_value(&self) -> &str {
        &self.raw_value
    }

    /// True when the field name is `name`, ASCII case-insensitively.
    ///
    /// ```
    /// # use mime_message::Header;
    /// let header = Header::new("X-Mailer", "mime-message")?;
    /// assert!(header.is("x-mailer"));
    /// assert!(!header.is("Mailer"));
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// Unfolds a raw value: continuation lines join with one space.
pub(crate) fn unfold(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for (index, line) in raw.split("\r\n").enumerate() {
        let line = line.trim();
        if index > 0 && !line.is_empty() {
            out.push(' ');
        }
        out.push_str(line);
    }
    out.trim().to_string()
}

fn check_name(name: &str) -> Result<()> {
    let valid = !name.is_empty() && name.bytes().all(crate::is_tchar);
    if valid {
        Ok(())
    } else {
        Err(Error::MalformedHeader(crate::truncate(name, 120)))
    }
}

fn check_value(name: &str, value: &str) -> Result<()> {
    let hostile = value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7F);
    if hostile {
        return Err(Error::ControlCharacter(name.to_string()));
    }
    Ok(())
}

/// Validates a raw value that may contain CRLF folds.
fn check_folded_value(name: &str, raw: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                // Only CRLF followed by WSP is a legal fold.
                if bytes.get(index + 1) != Some(&b'\n') {
                    return Err(Error::ControlCharacter(name.to_string()));
                }
                if !matches!(bytes.get(index + 2), Some(b' ' | b'\t')) {
                    return Err(Error::ControlCharacter(name.to_string()));
                }
                index += 2;
            }
            b'\n' => return Err(Error::ControlCharacter(name.to_string())),
            byte if (byte < 0x20 && byte != b'\t') || byte == 0x7F => {
                return Err(Error::ControlCharacter(name.to_string()));
            }
            _ => index += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfold_joins_continuations_with_one_space() {
        assert_eq!(unfold(" a"), "a");
        assert_eq!(unfold(" a\r\n b"), "a b");
        assert_eq!(unfold(" a\r\n\tb\r\n  c"), "a b c");
        assert_eq!(unfold(""), "");
        assert_eq!(unfold("   "), "");
    }

    #[test]
    fn new_trims_and_rejects_line_breaks() {
        assert_eq!(Header::new("X-A", "  y  ").unwrap().value(), "y");
        assert_eq!(Header::new("X-A", "  y  ").unwrap().raw_value(), " y");
        assert_eq!(Header::new("X-Empty", "").unwrap().raw_value(), "");
        assert!(matches!(
            Header::new("X-A", "a\nb"),
            Err(Error::ControlCharacter(_))
        ));
        assert!(matches!(
            Header::new("X-A", "a\u{0}b"),
            Err(Error::ControlCharacter(_))
        ));
        assert!(matches!(
            Header::new("X A", "x"),
            Err(Error::MalformedHeader(_))
        ));
        assert!(matches!(
            Header::new("", "x"),
            Err(Error::MalformedHeader(_))
        ));
        assert!(matches!(
            Header::new("X:A", "x"),
            Err(Error::MalformedHeader(_))
        ));
    }

    #[test]
    fn from_wire_accepts_folds_only_with_leading_whitespace() {
        assert!(Header::from_wire("X-A", " a\r\n b").is_ok());
        assert!(matches!(
            Header::from_wire("X-A", " a\r\nb"),
            Err(Error::ControlCharacter(_))
        ));
        assert!(matches!(
            Header::from_wire("X-A", " a\rb"),
            Err(Error::ControlCharacter(_))
        ));
        assert!(matches!(
            Header::from_wire("X-A", " a\n b"),
            Err(Error::ControlCharacter(_))
        ));
        assert!(matches!(
            Header::from_wire("X-A", " a\u{7f}b"),
            Err(Error::ControlCharacter(_))
        ));
    }

    #[test]
    fn eight_bit_values_survive_untouched() {
        let header = Header::from_wire("X-Gruss", "Müller").unwrap();
        assert_eq!(header.name(), "X-Gruss");
        assert_eq!(header.raw_value(), "Müller");
        assert_eq!(header.value(), "Müller");
    }

    #[test]
    fn non_ascii_names_are_rejected() {
        assert!(matches!(
            Header::new("X-Grüße", "x"),
            Err(Error::MalformedHeader(_))
        ));
    }
}
