//! Header fields that [`Message`](crate::Message) does not model itself.
//!
//! Everything the parser does not turn into a typed field (`From`, `To`,
//! `Subject`, …) is kept as a [`Header`] in the order it arrived, with the
//! original name casing, spacing and folding. Re-rendering such a message
//! reproduces those fields byte for byte, so a parsed mail can be forwarded
//! without losing `Reply-To`, `List-Unsubscribe`, `Authentication-Results` or
//! any other field the crate has no opinion about.

use crate::error::{Error, Result};
use crate::Limits;

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
    ///
    /// For untrusted input, prefer [`Header::new_with_limits`], which checks a
    /// byte budget before this constructor copies or trims the value.
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

    /// Creates a header field with an explicit [`Limits`] budget.
    ///
    /// The name and value are checked against [`Limits::max_header_bytes`]
    /// before either is copied, trimmed or unfolded. The result is the same as
    /// [`Header::new`] when both inputs fit the budget.
    ///
    /// ```
    /// use mime_message::{Header, Limits};
    ///
    /// let mut limits = Limits::default();
    /// limits.max_header_bytes = 4;
    ///
    /// assert!(Header::new_with_limits("X-A", "12", &limits).is_ok());
    /// assert!(Header::new_with_limits("X-Long", "1", &limits).is_err());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// In addition to the checks in [`Header::new`], returns
    /// [`Error::LimitExceeded`] when the name or value is longer than
    /// [`Limits::max_header_bytes`].
    pub fn new_with_limits(name: &str, value: &str, limits: &Limits) -> Result<Self> {
        check_header_input_size(name, value, limits)?;
        Self::new(name, value)
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
    ///
    /// For untrusted input, prefer [`Header::from_wire_with_limits`], which
    /// checks a byte budget before this constructor copies or unfolds the raw
    /// value.
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

    /// Builds a header from wire bytes with an explicit [`Limits`] budget.
    ///
    /// The name and raw value are checked against [`Limits::max_header_bytes`]
    /// before either is copied or the raw value is unfolded. The result is the
    /// same as [`Header::from_wire`] when both inputs fit the budget.
    ///
    /// ```
    /// use mime_message::{Header, Limits};
    ///
    /// let mut limits = Limits::default();
    /// limits.max_header_bytes = 13;
    ///
    /// assert!(Header::from_wire_with_limits("X-A", " fold\r\n\tvalue", &limits).is_ok());
    /// assert!(Header::from_wire_with_limits("X-A", "12345678901234", &limits).is_err());
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// In addition to the checks in [`Header::from_wire`], returns
    /// [`Error::LimitExceeded`] when the name or raw value is longer than
    /// [`Limits::max_header_bytes`].
    pub fn from_wire_with_limits(name: &str, raw_value: &str, limits: &Limits) -> Result<Self> {
        check_header_input_size(name, raw_value, limits)?;
        Self::from_wire(name, raw_value)
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
        let line = line.trim_matches(|ch| ch == ' ' || ch == '\t');
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
        Err(Error::malformed_name(name))
    }
}

/// Rejects an input larger than the caller's per-header byte budget.
///
/// The check runs before `Header::new_with_limits` / `from_wire_with_limits`
/// copy the inputs or unfold a raw value, so an oversized field costs one
/// length comparison rather than an attacker-sized allocation.
fn check_header_input_size(name: &str, value: &str, limits: &Limits) -> Result<()> {
    if name.len() > limits.max_header_bytes {
        return Err(Error::LimitExceeded {
            what: "header name bytes",
            limit: limits.max_header_bytes,
        });
    }
    if value.len() > limits.max_header_bytes {
        return Err(Error::LimitExceeded {
            what: "header value bytes",
            limit: limits.max_header_bytes,
        });
    }
    Ok(())
}

/// The first byte of `value` that a header value may not contain, if any.
///
/// A value is `text` (RFC 5322 §2.2): no NUL, CR, LF or any other control byte
/// below SP except tab, and no DEL. Bytes above `0x7f` are allowed — a value may
/// carry raw UTF-8 and the cleartext of a parsed message is often exactly that.
///
/// Returning the byte rather than a bare `bool` is what lets
/// [`Error::ControlCharacter`] say *which* byte was rejected; the folding check
/// below cannot use this helper, because a CR is legal there when it opens a
/// fold.
pub(crate) fn forbidden_value_byte(value: &str) -> Option<u8> {
    value.bytes().find(|byte| is_forbidden_byte(*byte))
}

/// True for the bytes RFC 5322 §2.2 keeps out of a field value.
///
/// Shared with the renderer, which checks a preserved header's raw value the
/// same way before writing it back out.
pub(crate) const fn is_forbidden_byte(byte: u8) -> bool {
    byte == 0x7F || (byte < 0x20 && byte != b'\t')
}

fn check_value(name: &str, value: &str) -> Result<()> {
    match forbidden_value_byte(value) {
        Some(byte) => Err(Error::control_value(name, byte)),
        None => Ok(()),
    }
}

/// Validates a raw value that may contain CRLF folds.
pub(crate) fn check_folded_value(name: &str, raw: &str) -> Result<()> {
    let bytes = raw.as_bytes();
    if bytes.starts_with(b"\r\n") {
        return Err(Error::control_value(name, b'\r'));
    }
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                // Only CRLF followed by WSP is a legal fold. A CR that opens
                // anything else is the byte reported: it is the one that has no
                // business being there.
                if bytes.get(index + 1) != Some(&b'\n')
                    || !matches!(bytes.get(index + 2), Some(b' ' | b'\t'))
                {
                    return Err(Error::control_value(name, b'\r'));
                }
                let mut after_wsp = index + 2;
                while matches!(bytes.get(after_wsp), Some(b' ' | b'\t')) {
                    after_wsp += 1;
                }
                if after_wsp == bytes.len() {
                    return Err(Error::control_value(name, b'\r'));
                }
                index += 2;
            }
            byte if is_forbidden_byte(byte) => {
                return Err(Error::control_value(name, byte));
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
        assert_eq!(unfold(" a\r\n \u{2000}b"), "a \u{2000}b");
        assert_eq!(unfold(""), "");
        assert_eq!(unfold("   "), "");
    }

    #[test]
    fn new_trims_and_rejects_line_breaks() {
        assert_eq!(Header::new("X-A", "  y  ").unwrap().value(), "y");
        assert_eq!(Header::new("X-A", "  y  ").unwrap().raw_value(), " y");
        assert_eq!(Header::new("X-Empty", "").unwrap().raw_value(), "");
        assert_eq!(
            Header::new("X-A", "a\nb").unwrap_err(),
            Error::ControlCharacter {
                name: "X-A".to_string(),
                byte: 0x0a,
            }
        );
        assert_eq!(
            Header::new("X-A", "a\u{0}b").unwrap_err(),
            Error::ControlCharacter {
                name: "X-A".to_string(),
                byte: 0x00,
            }
        );
        assert!(matches!(
            Header::new("X A", "x"),
            Err(Error::MalformedHeader { .. })
        ));
        assert!(matches!(
            Header::new("", "x"),
            Err(Error::MalformedHeader { .. })
        ));
        assert!(matches!(
            Header::new("X:A", "x"),
            Err(Error::MalformedHeader { .. })
        ));
    }

    #[test]
    fn from_wire_accepts_folds_only_with_leading_whitespace() {
        assert!(Header::from_wire("X-A", " a\r\n b").is_ok());
        for (broken, byte) in [
            (" a\r\nb", 0x0d),
            (" a\rb", 0x0d),
            (" a\n b", 0x0a),
            (" a\u{7f}b", 0x7f),
            (" a\r\n ", 0x0d),
            (" a\r\n\t", 0x0d),
            ("\r\n b", 0x0d),
        ] {
            assert_eq!(
                Header::from_wire("X-A", broken).unwrap_err(),
                Error::ControlCharacter {
                    name: "X-A".to_string(),
                    byte,
                },
                "{broken:?} must report 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn the_forbidden_byte_is_found_at_its_edges() {
        // Below SP except tab, plus DEL; every other byte is allowed, including
        // the eight-bit ones a raw UTF-8 value is made of.
        assert_eq!(forbidden_value_byte(""), None);
        assert_eq!(forbidden_value_byte("a\tb"), None);
        assert_eq!(forbidden_value_byte("a b"), None);
        assert_eq!(forbidden_value_byte("a\u{7e}b"), None);
        assert_eq!(forbidden_value_byte("a\u{1f}b"), Some(0x1f));
        assert_eq!(forbidden_value_byte("a\u{7f}b"), Some(0x7f));
        assert_eq!(forbidden_value_byte("a\u{0}b"), Some(0x00));
        // The first offending byte wins, wherever it sits in the value.
        assert_eq!(forbidden_value_byte("ok\u{0b} and\u{0c}"), Some(0x0b));
        // U+0085 is a Unicode control character, but neither of its bytes is a
        // control byte: this check is byte-wise, which is why the `Content-ID`
        // check reads characters and has its own answer for the same input.
        assert_eq!(forbidden_value_byte("Müller\u{85}"), None);
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
            Err(Error::MalformedHeader { .. })
        ));
    }

    #[test]
    fn bounded_constructors_reject_at_max_plus_one() {
        let limits = Limits {
            max_header_bytes: 5,
            ..Limits::default()
        };

        // The boundary is `>`, not `>=`: exactly the budget is accepted and one
        // byte more is refused, for the name and the value of both constructors.
        assert!(Header::new_with_limits("X-A", "12345", &limits).is_ok());
        assert_eq!(
            Header::new_with_limits("X-A", "123456", &limits).unwrap_err(),
            Error::LimitExceeded {
                what: "header value bytes",
                limit: 5,
            }
        );
        assert!(Header::new_with_limits("X-ABC", "1", &limits).is_ok());
        assert_eq!(
            Header::new_with_limits("X-ABCD", "1", &limits).unwrap_err(),
            Error::LimitExceeded {
                what: "header name bytes",
                limit: 5,
            }
        );

        assert!(Header::from_wire_with_limits("X-A", "12345", &limits).is_ok());
        assert_eq!(
            Header::from_wire_with_limits("X-A", "123456", &limits).unwrap_err(),
            Error::LimitExceeded {
                what: "header value bytes",
                limit: 5,
            }
        );
        assert!(Header::from_wire_with_limits("X-ABC", "1", &limits).is_ok());
        assert_eq!(
            Header::from_wire_with_limits("X-ABCD", "1", &limits).unwrap_err(),
            Error::LimitExceeded {
                what: "header name bytes",
                limit: 5,
            }
        );
    }
}
