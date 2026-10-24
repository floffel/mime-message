//! Parsing: edge-case matrix, MIME structure, security boundaries, concurrency.

use std::fmt::Write as _;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mime_message::{parse, parse_with_limits, Attachment, Error, Limits, Mailbox, Message};

fn header_only(headers: &str) -> String {
    format!("{headers}\r\n\r\n")
}

fn with_from(content: &str) -> String {
    format!("From: a@example.com\r\n{content}")
}

fn base64_of(text: &str) -> String {
    STANDARD.encode(text.as_bytes())
}

// ---------------------------------------------------------------------------
// Edge-case matrix: empty / headers-only / no body / line endings
// ---------------------------------------------------------------------------

#[test]
fn empty_and_blank_input_has_no_headers() {
    assert_eq!(parse("").unwrap_err(), Error::EmptyMessage);
    assert_eq!(parse("   ").unwrap_err(), Error::EmptyMessage);
    assert_eq!(parse("\r\n").unwrap_err(), Error::EmptyMessage);
    assert_eq!(parse("\r\n\r\nbody").unwrap_err(), Error::EmptyMessage);
    assert_eq!(parse("\n\n").unwrap_err(), Error::EmptyMessage);
}

#[test]
fn headers_only_has_empty_body() {
    let message = parse("From: a@example.com\r\nSubject: x").unwrap();
    assert_eq!(message.subject, "x");
    assert_eq!(message.body, "");
    assert!(message.attachments.is_empty());
}

#[test]
fn empty_body_after_blank_line() {
    let message = parse(&header_only("From: a@example.com")).unwrap();
    assert_eq!(message.body, "");
}

#[test]
fn missing_from_is_a_typed_error() {
    assert_eq!(
        parse(&header_only("Subject: x")).unwrap_err(),
        Error::EmptyHeader("From")
    );
    // A `From:` that parses to nothing is equally unusable.
    assert_eq!(
        parse(&header_only("From: undisclosed:;")).unwrap_err(),
        Error::EmptyHeader("From")
    );
}

#[test]
fn lf_and_cr_line_endings_parse_like_crlf() {
    let crlf =
        with_from("Subject: Grüße\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHallo\r\n");
    let lf = crlf.replace("\r\n", "\n");
    let cr = crlf.replace("\r\n", "\r");
    for raw in [crlf, lf, cr] {
        let message = parse(&raw).unwrap();
        assert_eq!(message.subject, "Grüße");
        assert_eq!(message.body.trim_end(), "Hallo");
    }
}

#[test]
fn tab_and_space_folded_headers_unfold() {
    let raw = "From: a@example.com\r\nSubject: eine\r\n\tsehr\r\n  lange\r\n\tZeile\r\n\r\nx";
    assert_eq!(parse(raw).unwrap().subject, "eine sehr lange Zeile");
}

#[test]
fn folded_headers_survive_render_parse_roundtrip() {
    let subject = "wort ".repeat(40).trim().to_string();
    let raw = String::from_utf8(
        Message::builder()
            .from("a@example.com")
            .unwrap()
            .to("b@example.com")
            .unwrap()
            .subject(subject.clone())
            .build()
            .unwrap()
            .render()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(parse(&raw).unwrap().subject, subject);
}

#[test]
fn eight_bit_body_without_charset_is_read_as_utf8() {
    let raw = with_from("Content-Type: text/plain\r\n\r\nGrüße aus München");
    assert_eq!(parse(&raw).unwrap().body, "Grüße aus München");
}

// ---------------------------------------------------------------------------
// Headers: duplicates, malformed, control characters, size
// ---------------------------------------------------------------------------

#[test]
fn duplicate_content_type_is_rejected() {
    let raw = with_from("Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nx");
    assert_eq!(
        parse(&raw).unwrap_err(),
        Error::DuplicateHeader("Content-Type".to_string())
    );
}

#[test]
fn duplicate_transfer_encoding_is_rejected() {
    let raw = with_from(
        "Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n\r\neA==",
    );
    assert_eq!(
        parse(&raw).unwrap_err(),
        Error::DuplicateHeader("Content-Transfer-Encoding".to_string())
    );
}

#[test]
fn duplicate_subject_keeps_the_first_value() {
    let raw = with_from("Subject: first\r\nSubject: second\r\n\r\nx");
    assert_eq!(parse(&raw).unwrap().subject, "first");
}

#[test]
fn malformed_headers_are_typed_errors() {
    assert!(matches!(
        parse("From a@example.com\r\n\r\nx"),
        Err(Error::MalformedHeader(_))
    ));
    assert!(matches!(
        parse("From : a@example.com\r\n\r\nx"),
        Err(Error::MalformedHeader(_))
    ));
    assert!(matches!(
        parse("\tindented continuation without header\r\n\r\nx"),
        Err(Error::MalformedHeader(_))
    ));
}

#[test]
fn control_characters_in_headers_are_rejected() {
    let raw = "From: a@example.com\r\nSubject: a\0b\r\n\r\nx";
    assert!(matches!(parse(raw), Err(Error::ControlCharacter(_))));
}

#[test]
fn overlong_header_line_hits_the_limit() {
    let subject = "a".repeat(20_000);
    let raw = with_from(&format!("Subject: {subject}\r\n\r\nx"));
    assert!(matches!(
        parse(&raw),
        Err(Error::LimitExceeded {
            what: "header line length",
            ..
        })
    ));
}

#[test]
fn overlong_header_block_hits_the_limit() {
    let mut raw = String::from("From: a@example.com\r\n");
    for index in 0..2000 {
        let _ = write!(raw, "X-Pad-{index}: {}\r\n", "b".repeat(60));
    }
    raw.push_str("\r\nx");
    assert!(matches!(
        parse(&raw),
        Err(Error::LimitExceeded {
            what: "header bytes",
            ..
        })
    ));
}

#[test]
fn too_many_headers_hit_the_limit() {
    let mut limits = Limits::default();
    limits.max_headers = 4;
    let raw = with_from("X-1: a\r\nX-2: b\r\nX-3: c\r\nX-4: d\r\n\r\nx");
    assert!(matches!(
        parse_with_limits(&raw, &limits),
        Err(Error::LimitExceeded {
            what: "header count",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

#[test]
fn addresses_with_comments_and_quoted_names() {
    let raw = with_from(
        "To: \"Doe, John\" <john@example.com>, jane@example.com (Jane Doe)\r\n\
         Cc: Team: a@example.com, b@example.com;\r\n\r\nx",
    );
    let message = parse(&raw).unwrap();
    assert_eq!(message.to[0].name.as_deref(), Some("Doe, John"));
    assert_eq!(message.to[0].address, "john@example.com");
    assert_eq!(message.to[1].name.as_deref(), Some("Jane Doe"));
    assert_eq!(message.to[1].address, "jane@example.com");
    assert_eq!(message.cc.len(), 2);
    assert_eq!(message.cc[1].address, "b@example.com");
}

#[test]
fn display_names_are_rfc2047_decoded() {
    let encoded = format!("=?UTF-8?B?{}?=", base64_of("Müller, Jörg"));
    let raw = with_from(&format!("To: {encoded} <jm@example.com>\r\n\r\nx"));
    assert_eq!(
        parse(&raw).unwrap().to[0].name.as_deref(),
        Some("Müller, Jörg")
    );
}

#[test]
fn invalid_addresses_are_rejected() {
    for invalid in ["no-at-sign", "a@", "@b", "a b@example.com", "a@b@c"] {
        let raw = with_from(&format!("To: {invalid}\r\n\r\nx"));
        assert!(
            matches!(parse(&raw), Err(Error::InvalidMailbox(_))),
            "{invalid} must be rejected"
        );
    }
}

#[test]
fn thousand_recipients_parse() {
    let mut to = String::new();
    for index in 0..1000 {
        if index > 0 {
            to.push(',');
        }
        if index % 10 == 0 {
            // Keep lines inside the header-line budget by folding.
            to.push_str("\r\n ");
        }
        let _ = write!(to, "user{index}@example.com");
    }
    let raw = with_from(&format!("To:{to}\r\n\r\nx"));
    let message = parse(&raw).unwrap();
    assert_eq!(message.to.len(), 1000);
    assert_eq!(message.to[999].address, "user999@example.com");
}

// ---------------------------------------------------------------------------
// Transfer encodings
// ---------------------------------------------------------------------------

#[test]
fn base64_body_decodes_across_lines() {
    let encoded = base64_of("Hallo Welt, Grüße!");
    let wrapped = encoded
        .as_bytes()
        .chunks(16)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n");
    let raw = with_from(&format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{wrapped}\r\n"
    ));
    assert_eq!(parse(&raw).unwrap().body, "Hallo Welt, Grüße!");
}

#[test]
fn invalid_base64_is_a_typed_error() {
    let raw = with_from("Content-Transfer-Encoding: base64\r\n\r\n!!!!not base64!!!!");
    assert_eq!(parse(&raw).unwrap_err(), Error::InvalidBase64);
}

#[test]
fn quoted_printable_body_decodes_with_its_charset() {
    let raw = with_from(
        "Content-Type: text/plain; charset=iso-8859-1\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\nGr=FC=DFe=\r\n aus M=FCnchen",
    );
    assert_eq!(parse(&raw).unwrap().body, "Grüße aus München");
}

#[test]
fn windows_1252_quoted_printable_decodes() {
    let raw = with_from(
        "Content-Type: text/plain; charset=windows-1252\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n=93Hallo=94",
    );
    assert_eq!(parse(&raw).unwrap().body, "\u{201C}Hallo\u{201D}");
}

#[test]
fn unknown_transfer_encoding_is_a_typed_error() {
    let raw = with_from("Content-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x");
    assert_eq!(
        parse(&raw).unwrap_err(),
        Error::UnsupportedTransferEncoding("x-uuencode".to_string())
    );
}

#[test]
fn seven_and_eight_bit_are_passed_through() {
    for encoding in ["7bit", "8bit", "binary", "BASE64 (comment)"] {
        let raw = if encoding.starts_with("BASE64") {
            with_from(&format!(
                "Content-Transfer-Encoding: {encoding}\r\n\r\neA=="
            ))
        } else {
            with_from(&format!(
                "Content-Transfer-Encoding: {encoding}\r\n\r\nplain"
            ))
        };
        let message = parse(&raw).unwrap();
        if encoding.starts_with("BASE64") {
            assert_eq!(message.body, "x");
        } else {
            assert_eq!(message.body, "plain");
        }
    }
}

// ---------------------------------------------------------------------------
// Multipart structure
// ---------------------------------------------------------------------------

const MIXED: &str = concat!(
    "From: Shop <shop@example.com>\r\n",
    "To: kunde@example.com\r\n",
    "Subject: Rechnung\r\n",
    "MIME-Version: 1.0\r\n",
    "Content-Type: multipart/mixed; boundary=\"=_b\"\r\n",
    "\r\n",
    "This is a preamble that must be ignored.\r\n",
    "--=_b\r\n",
    "Content-Type: text/plain; charset=utf-8\r\n",
    "Content-Transfer-Encoding: 8bit\r\n",
    "\r\n",
    "Anbei die Rechnung.\r\n",
    "--=_b\r\n",
    "Content-Type: application/pdf\r\n",
    "Content-Transfer-Encoding: base64\r\n",
    "Content-Disposition: attachment; filename=\"rechnung.pdf\"\r\n",
    "\r\n",
    "JVBERi0xLjQ=\r\n",
    "--=_b--\r\n",
    "epilogue ignored\r\n",
);

#[test]
fn multipart_mixed_body_and_attachment() {
    let message = parse(MIXED).unwrap();
    assert_eq!(message.from.name.as_deref(), Some("Shop"));
    assert_eq!(message.body, "Anbei die Rechnung.");
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].filename, "rechnung.pdf");
    assert_eq!(message.attachments[0].content_type, "application/pdf");
    assert_eq!(message.attachments[0].data, b"%PDF-1.4");
}

#[test]
fn multipart_alternative_prefers_plain_text_and_keeps_html() {
    let raw = with_from(concat!(
        "Content-Type: multipart/alternative; boundary=alt\r\n\r\n",
        "--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHallo\r\n",
        "--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hallo</p>\r\n",
        "--alt--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "Hallo");
    assert_eq!(message.html_body.as_deref(), Some("<p>Hallo</p>"));
    assert!(message.attachments.is_empty());
}

#[test]
fn multipart_related_inline_image_becomes_an_attachment() {
    let raw = with_from(concat!(
        "Content-Type: multipart/related; boundary=rel\r\n\r\n",
        "--rel\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<img src=\"cid:x\">\r\n",
        "--rel\r\nContent-Type: image/png\r\nContent-ID: <x>\r\n\
         Content-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n",
        "--rel--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.html_body.as_deref(), Some("<img src=\"cid:x\">"));
    assert_eq!(message.body, "");
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].content_type, "image/png");
    assert_eq!(message.attachments[0].data, b"\x89PNG\r\n\x1a\n");
}

#[test]
fn nested_multipart_flattens_to_body_and_attachments() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=outer\r\n\r\n",
        "--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n",
        "--inner\r\nContent-Type: text/plain\r\n\r\nplain body\r\n",
        "--inner\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n",
        "--inner--\r\n",
        "--outer\r\nContent-Type: application/octet-stream; name=\"blob.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n",
        "--outer--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "plain body");
    assert_eq!(message.html_body.as_deref(), Some("<b>html</b>"));
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].filename, "blob.bin");
    assert_eq!(message.attachments[0].data, [0, 1, 2, 3]);
}

#[test]
fn text_attachment_is_not_mistaken_for_the_body() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\r\nnotes\r\n",
        "--b--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "body");
    assert_eq!(message.attachments.len(), 1);
    assert_eq!(message.attachments[0].filename, "notes.txt");
    assert_eq!(message.attachments[0].data, b"notes");
}

#[test]
fn attachment_without_filename_gets_a_part_name() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: application/octet-stream\r\n\r\nraw\r\n",
        "--b--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.attachments[0].filename, "part-1");
}

#[test]
fn rfc2231_continuation_filename() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: application/pdf\r\n\
         Content-Disposition: attachment; filename*0*=utf-8''Rech; filename*1*=nung.pdf\r\n\r\n\r\n",
        "--b--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().attachments[0].filename, "Rechnung.pdf");
}

#[test]
fn rfc2231_single_extended_filename() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: image/png\r\n\
         Content-Disposition: attachment; filename*=iso-8859-1''Gr%FCn.png\r\n\r\nx\r\n",
        "--b--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().attachments[0].filename, "Grün.png");
}

#[test]
fn name_parameter_is_used_when_disposition_has_no_filename() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: application/pdf; name=\"from-name.pdf\"\r\n\r\ndata\r\n",
        "--b--\r\n",
    ));
    assert_eq!(
        parse(&raw).unwrap().attachments[0].filename,
        "from-name.pdf"
    );
}

#[test]
fn missing_boundary_is_a_typed_error() {
    let raw = with_from("Content-Type: multipart/mixed\r\n\r\n--x\r\n\r\ny\r\n--x--");
    assert_eq!(parse(&raw).unwrap_err(), Error::MissingBoundary);
}

#[test]
fn truncated_multipart_is_a_typed_error() {
    let raw =
        with_from("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nnever closed\r\n");
    assert_eq!(parse(&raw).unwrap_err(), Error::UnterminatedMultipart);
}

#[test]
fn invalid_content_type_is_a_typed_error() {
    let raw = with_from("Content-Type: text\r\n\r\nx");
    assert!(matches!(parse(&raw), Err(Error::InvalidContentType(_))));
}

#[test]
fn boundary_with_spaces_and_trailing_padding() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=\"a b\"\r\n\r\n",
        "--a b  \r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--a b--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().body, "body");
}

#[test]
fn empty_part_body_is_allowed() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\n",
        "--b\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n",
        "--b--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "");
    assert_eq!(message.attachments[0].data, b"data");
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[test]
fn encoded_word_cannot_smuggle_a_header() {
    let smuggled = base64_of("harmless\r\nBcc: attacker@example.com");
    let raw = with_from(&format!("Subject: =?UTF-8?B?{smuggled}?=\r\n\r\nx"));
    assert_eq!(parse(&raw).unwrap_err(), Error::HeaderInjection("Subject"));
}

#[test]
fn encoded_word_cannot_smuggle_a_recipient_via_display_name() {
    let smuggled = base64_of("x\r\nBcc: attacker@example.com");
    let raw = with_from(&format!(
        "To: =?UTF-8?B?{smuggled}?= <victim@example.com>\r\n\r\nx"
    ));
    assert_eq!(parse(&raw).unwrap_err(), Error::HeaderInjection("To"));
}

#[test]
fn unicode_line_separators_in_decoded_headers_are_rejected() {
    for separator in ['\u{85}', '\u{2028}', '\u{2029}'] {
        let smuggled = base64_of(&format!("a{separator}b"));
        let raw = with_from(&format!("Subject: =?UTF-8?B?{smuggled}?=\r\n\r\nx"));
        assert_eq!(parse(&raw).unwrap_err(), Error::HeaderInjection("Subject"));
    }
}

#[test]
fn attachment_filename_path_traversal_is_rejected() {
    for name in [
        "../../etc/passwd",
        // Doubled backslashes: inside a quoted-string `\x` is an escape, so the
        // attacker has to write `\\` to get a real separator through.
        "..\\\\..\\\\windows\\\\system32\\\\x",
        "/abs/path",
        "C:autoexec.bat",
        "..",
    ] {
        let raw = with_from(&format!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n\
             --b\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
             --b\r\nContent-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"{name}\"\r\n\r\ndata\r\n--b--\r\n"
        ));
        assert!(
            matches!(parse(&raw), Err(Error::UnsafeFilename(_))),
            "{name} must be rejected"
        );
    }
}

#[test]
fn depth_bomb_hits_the_limit() {
    fn nested(depth: usize, bottom: usize) -> String {
        if depth == bottom {
            return "Content-Type: text/plain\r\n\r\nleaf\r\n".to_string();
        }
        let boundary = format!("b{depth}");
        format!(
            "Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n\
             --{boundary}\r\n{inner}--{boundary}--\r\n",
            inner = nested(depth + 1, bottom)
        )
    }
    let raw = with_from(&nested(0, 40));
    assert!(matches!(
        parse(&raw),
        Err(Error::LimitExceeded {
            what: "nesting depth",
            ..
        })
    ));
}

#[test]
fn part_count_bomb_hits_the_limit() {
    let mut raw =
        String::from("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n");
    for _ in 0..1200 {
        raw.push_str("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n");
    }
    raw.push_str("--b--\r\n");
    assert!(matches!(
        parse(&raw),
        Err(Error::LimitExceeded {
            what: "part count",
            ..
        })
    ));
}

#[test]
fn body_size_bomb_hits_the_limit() {
    let mut limits = Limits::default();
    limits.max_body_bytes = 32;
    let raw = with_from(&format!("\r\n{}", "a".repeat(1024)));
    assert!(matches!(
        parse_with_limits(&raw, &limits),
        Err(Error::LimitExceeded {
            what: "body bytes",
            ..
        })
    ));
}

#[test]
fn base64_body_size_bomb_hits_the_limit() {
    let mut limits = Limits::default();
    limits.max_body_bytes = 64;
    let encoded = STANDARD.encode(vec![b'x'; 4096]);
    let raw = with_from(&format!(
        "Content-Transfer-Encoding: base64\r\n\r\n{encoded}"
    ));
    assert!(parse_with_limits(&raw, &limits).is_err());
}

// ---------------------------------------------------------------------------
// Round-trip through the renderer
// ---------------------------------------------------------------------------

#[test]
fn builder_render_parse_roundtrip_simple() {
    let built = Message::builder()
        .from("Shop <shop@example.com>")
        .unwrap()
        .to("kunde@example.com")
        .unwrap()
        .subject("Ihre Rechnung")
        .body("Anbei die Rechnung.")
        .date("Tue, 21 Oct 2026 10:00:00 +0000")
        .message_id("<abc@example.com>")
        .build()
        .unwrap();
    let raw = String::from_utf8(built.render().unwrap()).unwrap();
    assert_eq!(parse(&raw).unwrap(), built);
}

#[test]
fn builder_render_parse_roundtrip_with_alternative_and_attachment() {
    let built = Message::builder()
        .from("Müller, Jörg <jm@example.com>")
        .unwrap()
        .to("a@example.com")
        .unwrap()
        .cc("b@example.com")
        .unwrap()
        .subject("Grüße aus München")
        .body("Hallo\nWelt")
        .html_body("<p>Hallo</p>")
        .attachment(Attachment::new(
            "rechnung.pdf",
            "application/pdf",
            b"%PDF-1.4\x00\x01".to_vec(),
        ))
        .build()
        .unwrap();
    let raw = String::from_utf8(built.render().unwrap()).unwrap();
    let parsed = parse(&raw).unwrap();
    assert_eq!(parsed.from, built.from);
    assert_eq!(parsed.cc, built.cc);
    assert_eq!(parsed.subject, built.subject);
    assert_eq!(parsed.html_body.as_deref(), Some("<p>Hallo</p>"));
    assert_eq!(parsed.attachments, built.attachments);
    // The renderer normalises the body to CRLF.
    assert_eq!(parsed.body, "Hallo\r\nWelt");
}

#[test]
fn parsing_a_rendered_message_keeps_mailboxes_with_awkward_names() {
    let built = Message {
        from: Mailbox {
            name: Some("a \"quoted\", name".to_string()),
            address: "a@example.com".to_string(),
        },
        to: vec![Mailbox {
            name: Some("Back\\slash".to_string()),
            address: "b@example.com".to_string(),
        }],
        cc: Vec::new(),
        subject: "x".to_string(),
        body: "y".to_string(),
        html_body: None,
        date: None,
        message_id: None,
        attachments: Vec::new(),
    };
    let raw = String::from_utf8(built.render().unwrap()).unwrap();
    assert_eq!(parse(&raw).unwrap(), built);
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn parsing_is_send_sync_and_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Message>();
    assert_send_sync::<Error>();
    assert_send_sync::<Limits>();

    let raw: Arc<str> = Arc::from(MIXED);
    let expected = parse(&raw).unwrap();
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let raw = Arc::clone(&raw);
            let expected = expected.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(parse(&raw).unwrap(), expected);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// Coverage corners: branches that only exotic-but-legal input reaches
// ---------------------------------------------------------------------------

#[test]
fn message_methods_mirror_the_free_functions() {
    assert_eq!(Message::parse(MIXED).unwrap(), parse(MIXED).unwrap());
    let mut limits = Limits::default();
    limits.max_depth = 8;
    assert_eq!(
        Message::parse_with_limits(MIXED, &limits).unwrap(),
        parse_with_limits(MIXED, &limits).unwrap()
    );
}

#[test]
fn duplicate_to_headers_are_joined() {
    let raw = with_from("To: a@example.com\r\nTo: b@example.com\r\n\r\nx");
    let message = parse(&raw).unwrap();
    assert_eq!(message.to.len(), 2);
    assert_eq!(message.to[1].address, "b@example.com");
}

#[test]
fn multipart_container_with_its_own_transfer_encoding() {
    let inner = concat!(
        "--b\r\nContent-Type: text/plain\r\n\r\nencoded container\r\n",
        "--b--\r\n",
    );
    let encoded = STANDARD.encode(inner);
    let raw = with_from(&format!(
        "Content-Type: multipart/mixed; boundary=b\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{encoded}"
    ));
    assert_eq!(parse(&raw).unwrap().body, "encoded container");
}

#[test]
fn duplicate_text_and_html_parts_become_attachments() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nsecond\r\n",
        "--b\r\nContent-Type: text/html\r\n\r\n<p>one</p>\r\n",
        "--b\r\nContent-Type: text/html\r\n\r\n<p>two</p>\r\n",
        "--b--\r\n",
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "first");
    assert_eq!(message.html_body.as_deref(), Some("<p>one</p>"));
    assert_eq!(message.attachments.len(), 2);
    assert_eq!(message.attachments[0].data, b"second");
    assert_eq!(message.attachments[1].data, b"<p>two</p>");
}

#[test]
fn html_only_message_has_no_plain_body() {
    let raw = with_from("Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>");
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "");
    assert_eq!(message.html_body.as_deref(), Some("<p>hi</p>"));
}

#[test]
fn quoted_local_part_is_accepted() {
    let raw = with_from("To: \"a b\"@example.com\r\n\r\nx");
    assert_eq!(parse(&raw).unwrap().to[0].address, "\"a b\"@example.com");
}

#[test]
fn unterminated_angle_bracket_is_rejected() {
    let raw = with_from("To: Name <a@example.com\r\n\r\nx");
    assert!(matches!(parse(&raw), Err(Error::InvalidMailbox(_))));
}

#[test]
fn unterminated_quotes_and_comments_are_tolerated() {
    let quoted = with_from("To: \"a@example.com\r\n\r\nx");
    assert!(parse(&quoted).is_ok());

    let commented = with_from("To: a@example.com (unterminated\r\n\r\nx");
    let message = parse(&commented).unwrap();
    assert_eq!(message.to[0].address, "a@example.com");
    assert_eq!(message.to[0].name.as_deref(), Some("unterminated"));
}

#[test]
fn content_type_with_comments_junk_and_quoting() {
    let raw = with_from(concat!(
        "Content-Type: text/plain (a comment); charset=utf-8; broken; =x; charset2=\"utf-8\";\r\n\r\n",
        "body"
    ));
    let message = parse(&raw).unwrap();
    assert_eq!(message.body, "body");
}

#[test]
fn content_type_with_quoted_semicolon() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=\"b;1\"\r\n\r\n",
        "--b;1\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b;1--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().body, "body");
}

#[test]
fn lf_only_and_cr_only_multipart_bodies() {
    let crlf = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b--\r\n",
    ));
    for raw in [crlf.replace("\r\n", "\n"), crlf.replace("\r\n", "\r")] {
        assert_eq!(parse(&raw).unwrap().body, "body");
    }
}

#[test]
fn rfc2231_plain_continuation_segments() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename*0=\"Rech\"; filename*1=\"nung.pdf\"\r\n\r\ndata\r\n",
        "--b--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().attachments[0].filename, "Rechnung.pdf");
}

#[test]
fn percent_decoding_accepts_lowercase_hex() {
    let raw = with_from(concat!(
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
        "--b\r\nContent-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename*=utf-8''%41%42.pdf\r\n\r\ndata\r\n",
        "--b--\r\n",
    ));
    assert_eq!(parse(&raw).unwrap().attachments[0].filename, "AB.pdf");
}

#[test]
fn mailbox_parse_rejects_reversed_brackets() {
    assert_eq!(
        Message::builder().from("a>b<c@d").unwrap_err(),
        Error::InvalidMailbox("a>b<c@d".to_string())
    );
}
