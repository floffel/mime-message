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
use std::hash::{Hash, Hasher};

/// RFC 5322 §2.1.1: a physical header line MUST be at most 998 octets.
const MAX_HEADER_LINE_BYTES: usize = 998;

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
/// Headers compare and hash by field identity: their names ASCII
/// case-insensitively and their unfolded values. Name casing, raw spacing and
/// folding are preserved for rendering, but do not make two views of the same
/// header field different.
#[derive(Debug, Clone)]
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
    /// The value is trimmed of ASCII space and horizontal tab characters; empty
    /// values are allowed (`X-Empty:` is a valid header). Other whitespace,
    /// including Unicode whitespace such as NBSP, is preserved. Line breaks are
    /// rejected: a header cannot smuggle a second one.
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
        let trimmed = trim_header_sp(&value);
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
    /// with whitespace, and control characters other than tab, including the
    /// Unicode line separators U+0085, U+2028 and U+2029.
    ///
    /// For untrusted input, prefer [`Header::from_wire_with_limits`], which
    /// checks a byte budget before this constructor copies or unfolds the raw
    /// value.
    pub fn from_wire(name: impl Into<String>, raw_value: impl Into<String>) -> Result<Self> {
        let name = name.into();
        check_name(&name)?;
        let raw_value = raw_value.into();
        check_raw_value(&name, &raw_value)?;
        Ok(Self::from_wire_after_raw_check(name, raw_value))
    }

    /// Builds a header from wire fields whose name and raw value have already
    /// passed [`check_raw_value`].
    pub(crate) fn from_wire_after_raw_check(name: String, raw_value: String) -> Self {
        debug_assert!(check_name(&name).is_ok());
        debug_assert!(check_raw_value(&name, &raw_value).is_ok());
        Self {
            value: unfold(&raw_value),
            name,
            raw_value,
        }
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
    /// Only ASCII folding whitespace (spaces and tabs) is trimmed from the ends.
    /// Non-ASCII whitespace such as U+00A0 is part of the value and is kept, so
    /// a rendered value round-trips byte for byte.
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

impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.is(&other.name) && self.value == other.value
    }
}

impl Eq for Header {}

impl Hash for Header {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.to_ascii_lowercase().hash(state);
        self.value.hash(state);
    }
}

/// Trims the ASCII folding whitespace (FWS) at both ends of `text`.
///
/// `fold_header` only ever folds at an ASCII space, and the per-line trim below
/// only removes ASCII FWS, so the final trim has to agree: a Unicode whitespace
/// character such as U+00A0 is part of the value and must survive unfolding.
fn trim_header_sp(value: &str) -> &str {
    value.trim_matches(|ch| ch == ' ' || ch == '\t')
}

/// Unfolds a raw value: continuation lines join with one space.
pub(crate) fn unfold(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for (index, line) in raw.split("\r\n").enumerate() {
        let line = trim_header_sp(line);
        if index > 0 && !line.is_empty() {
            out.push(' ');
        }
        out.push_str(line);
    }
    trim_header_sp(&out).to_string()
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
/// [`Error::ControlCharacter`] say *which* byte was rejected;
/// [`check_raw_value`] cannot use this helper, because a CR is legal there when
/// it opens a fold.
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

/// True when `value` contains a character a header value cannot carry.
///
/// The byte-wise [`forbidden_value_byte`] check predates this one and is kept
/// for the exact-byte payload on ASCII controls. This check is the character
/// view the modelled-header validator, the renderer and the raw-wire constructor
/// all share, so U+0085/U+2028/U+2029 cannot slip through as multi-byte UTF-8.
pub(crate) fn has_forbidden_chars(value: &str) -> bool {
    value.chars().any(is_forbidden_char)
}

fn is_forbidden_char(ch: char) -> bool {
    matches!(ch, '\r' | '\n' | '\0' | '\u{85}' | '\u{2028}' | '\u{2029}')
        || (ch.is_control() && ch != '\t')
}

/// The byte a character-aware rejection reports for `ch`.
///
/// For ASCII controls this is the byte itself. A non-ASCII character has no
/// single byte, so the first byte of its UTF-8 encoding identifies it.
fn utf8_lead_byte(ch: char) -> u8 {
    let mut encoded = [0_u8; 4];
    ch.encode_utf8(&mut encoded);
    encoded[0]
}

/// Validates a header value exactly as it appears on the wire.
///
/// A raw value may contain CRLF only when it opens a fold, and may not contain
/// other control characters, including the Unicode line separators that are not
/// ASCII control bytes. Every wire-value path uses this one predicate:
/// [`Header::from_wire`], the parser's header-block reader and the renderer's
/// preserved-header guard.
pub(crate) fn check_raw_value(name: &str, raw: &str) -> Result<()> {
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
            byte if byte.is_ascii() => {
                index += 1;
            }
            _ => {
                let ch = raw[index..]
                    .chars()
                    .next()
                    .expect("index is a valid UTF-8 boundary");
                if is_forbidden_char(ch) {
                    return Err(Error::control_value(name, utf8_lead_byte(ch)));
                }
                index += ch.len_utf8();
            }
        }
    }
    Ok(())
}

/// Validates a preserved header as it will appear on the wire.
///
/// Preserved headers are re-emitted byte for byte, so this is the shared guard
/// for both the mutation APIs and the renderer: controls are rejected exactly as
/// in [`check_raw_value`], and every physical line (`name:` on the first line,
/// any folded continuation afterwards) must fit RFC 5322 §2.1.1's 998-octet
/// hard limit.
pub(crate) fn check_rendered_header(name: &str, raw: &str) -> Result<()> {
    check_raw_value(name, raw)?;

    let mut lines = raw.split("\r\n");
    let first = lines.next().unwrap_or(raw);
    if name.len() + 1 + first.len() > MAX_HEADER_LINE_BYTES {
        return Err(Error::LimitExceeded {
            what: "header line length",
            limit: MAX_HEADER_LINE_BYTES,
        });
    }
    for line in lines {
        if line.len() > MAX_HEADER_LINE_BYTES {
            return Err(Error::LimitExceeded {
                what: "header line length",
                limit: MAX_HEADER_LINE_BYTES,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
    fn unfold_trims_ascii_fws_only() {
        // A non-ASCII whitespace character is part of the value, whether it
        // sits inside a line or ends one, so folding and unfolding agree.
        assert_eq!(unfold(" a\u{a0}b"), "a\u{a0}b");
        assert_eq!(unfold(" \u{a0}a"), "\u{a0}a");
        assert_eq!(unfold(" a\u{a0}"), "a\u{a0}");
        assert_eq!(unfold(" a\u{2000}"), "a\u{2000}");
        // A continuation line made of non-ASCII whitespace survives the join.
        assert_eq!(unfold(" a\r\n \u{a0}"), "a \u{a0}");
        // ASCII FWS at the very ends is still stripped.
        assert_eq!(unfold("\t a \t"), "a");
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
    fn new_trims_only_ascii_space_and_tab() {
        let header = Header::new("Subject", "\u{a0}Rechnung").unwrap();
        assert_eq!(header.value(), "\u{a0}Rechnung");
        assert_eq!(header.raw_value(), " \u{a0}Rechnung");

        let header = Header::new("Subject", "\t\u{2000}Rechnung ").unwrap();
        assert_eq!(header.value(), "\u{2000}Rechnung");
    }

    #[test]
    fn equality_and_hash_match_header_identity() {
        let built = Header::new("x-a", "  y  ").unwrap();
        let parsed = Header::from_wire("X-A", "  y  ").unwrap();
        assert_eq!(built, parsed);
        assert_eq!(Header::new("X-A", "y").unwrap(), built);

        let mut seen = HashSet::new();
        seen.insert(built);
        seen.insert(parsed);
        assert_eq!(seen.len(), 1);
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
