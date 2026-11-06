//! DKIM tests, anchored on the published RFC examples rather than on our own
//! round-trips: a signer and verifier that agree with each other prove nothing
//! about the wire format.
//!
//! Vector: RFC 8463 Appendix A.3 — RSA-SHA256 and Ed25519-SHA256 side by side,
//! `relaxed/relaxed`, with the keys from A.1/A.2 (`tests/fixtures/rfc8463-a3.eml`).
//!
//! RFC 6376 Appendix A.2 is *not* used: its `b=` value does not verify against
//! the message printed next to it under any reconstruction of the folding we
//! tried (its private key is redacted, so the figure is illustrative). The
//! `simple/simple` path it would cover is pinned by hand-written canonical
//! inputs in `src/dkim.rs` instead, and interop is proven by the RFC 8463 RSA
//! vector above.

#![cfg(feature = "dkim")]

use mime_message::dkim::{self, Canonicalization, SignParams, SigningKey, VerifyingKey};
use mime_message::{
    Attachment, Error, Header, KeyRejected, Message, SignatureCause, SignatureDefect,
};

const RFC8463_MESSAGE: &str = include_str!("fixtures/rfc8463-a3.eml");
const RFC8463_RSA_RECORD: &str = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";
const RFC8463_ED25519_RECORD: &str =
    "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/{name}"))
        .unwrap_or_else(|error| panic!("fixture {name}: {error}"))
}

fn rsa_signing_key() -> SigningKey {
    let pem = fixture("rsa-private.pem");
    SigningKey::from_pem(&pem).expect("the fixture key parses")
}

fn sample_message() -> Message {
    Message::builder()
        .from("Shop <shop@example.com>")
        .expect("from")
        .to("kunde@example.com")
        .expect("to")
        .subject("Ihre Rechnung")
        .body("Anbei die Rechnung.\n")
        .date("Tue, 21 Oct 2026 10:00:00 +0000")
        .message_id("<abc@example.com>")
        .build()
        .expect("build")
}

// ---------------------------------------------------------------------------
// Published vectors
// ---------------------------------------------------------------------------

#[test]
fn rfc8463_appendix_a3_ed25519_signature_verifies() {
    let key = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("ed25519 record");
    let verified = dkim::verify(RFC8463_MESSAGE, &key).expect("RFC 8463 ed25519 must verify");
    assert_eq!(verified.domain, "football.example.com");
    assert_eq!(verified.selector, "brisbane");
    assert_eq!(verified.algorithm.as_str(), "ed25519-sha256");
    assert_eq!(verified.timestamp, Some(1_528_637_909));
    // The h= tag repeats from/subject/date on purpose (oversigning).
    assert_eq!(
        verified.signed_headers,
        [
            "from",
            "to",
            "subject",
            "date",
            "message-id",
            "from",
            "subject",
            "date"
        ]
    );
}

#[test]
fn rfc8463_appendix_a3_rsa_signature_verifies() {
    let key = VerifyingKey::from_dns_record(RFC8463_RSA_RECORD).expect("rsa record");
    // The Ed25519 signature comes first and cannot be checked with this key;
    // the RSA one must still verify.
    let verified = dkim::verify(RFC8463_MESSAGE, &key).expect("RFC 8463 rsa must verify");
    assert_eq!(verified.selector, "test");
    assert_eq!(verified.algorithm.as_str(), "rsa-sha256");
}

#[test]
fn rfc8463_tampering_breaks_both_signatures() {
    let ed = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("record");
    let rsa = VerifyingKey::from_dns_record(RFC8463_RSA_RECORD).expect("record");
    let tampered = RFC8463_MESSAGE.replace("Joe.", "Joseph.");
    assert_eq!(
        dkim::verify(&tampered, &ed).unwrap_err(),
        Error::BodyHashMismatch {
            domain: "football.example.com".to_string(),
            selector: "brisbane".to_string(),
        }
    );
    assert_eq!(
        dkim::verify(&tampered, &rsa).unwrap_err(),
        Error::BodyHashMismatch {
            domain: "football.example.com".to_string(),
            selector: "test".to_string(),
        }
    );
}

#[test]
fn a_third_party_signed_message_verifies_with_the_public_key_only() {
    // Same vector, but reached through the DNS record form a verifier really
    // has, and through `Message::parse` to prove the parser keeps the header
    // block intact.
    let parsed = Message::parse(RFC8463_MESSAGE).expect("parses");
    assert!(parsed
        .headers()
        .iter()
        .any(|header| header.is("DKIM-Signature")));
    assert!(parsed
        .headers()
        .iter()
        .any(|header| header.is("DKIM-Signature")));
    let key = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("record");
    assert!(dkim::verify(RFC8463_MESSAGE, &key).is_ok());
}

// ---------------------------------------------------------------------------
// Round-trips we control
// ---------------------------------------------------------------------------

#[test]
fn ed25519_sign_then_verify_roundtrip() {
    // The RFC 8463 secret key, used from its base64 form.
    let key = SigningKey::from_ed25519_seed_base64("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
        .expect("seed");
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    let verified = dkim::verify(&raw, &key.verifying_key()).expect("verify");
    assert_eq!(verified.domain, "example.com");
    assert_eq!(verified.selector, "sel");
}

#[test]
fn rsa_sign_then_verify_roundtrip() {
    let key = rsa_signing_key();
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "rsa").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    // Verify with the public key from the DNS record, as a receiver would.
    let record = key.dns_record();
    let public = VerifyingKey::from_dns_record(&record).expect("record");
    let verified = dkim::verify(&raw, &public).expect("verify");
    assert_eq!(verified.algorithm.as_str(), "rsa-sha256");
}

#[test]
fn every_canonicalization_pair_round_trips() {
    let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
    for header in [Canonicalization::Simple, Canonicalization::Relaxed] {
        for body in [Canonicalization::Simple, Canonicalization::Relaxed] {
            let params = SignParams::new("example.com", "sel")
                .expect("params")
                .canonicalization(header, body);
            let signed = sample_message().sign(&key, &params).expect("sign");
            let raw = String::from_utf8(signed).expect("utf-8");
            assert!(
                dkim::verify(&raw, &key.verifying_key()).is_ok(),
                "{header:?}/{body:?} must verify"
            );
        }
    }
}

#[test]
fn relaxed_survives_the_changes_it_is_meant_to_absorb() {
    let key = SigningKey::from_ed25519_seed(&[11u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("params")
        .canonicalization(Canonicalization::Relaxed, Canonicalization::Relaxed);
    let signed = sample_message().sign(&key, &params).expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");

    // Re-fold a signed header and add trailing whitespace to the body: relaxed
    // canonicalization must still verify both.
    let refolded = raw.replace("Subject: Ihre Rechnung", "SUBJECT:  Ihre\r\n Rechnung");
    // (Subject was encoded; rebuild it if the naive replacement missed.)
    let altered_body = raw.replace("Anbei die Rechnung.", "Anbei die Rechnung.   ");
    for candidate in [refolded, altered_body] {
        let key = key.verifying_key();
        let verified = dkim::verify(&candidate, &key);
        assert!(
            verified.is_ok(),
            "relaxed verification failed: {verified:?}"
        );
    }
}

#[test]
fn simple_rejects_refolding() {
    let key = SigningKey::from_ed25519_seed(&[13u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("params")
        .canonicalization(Canonicalization::Simple, Canonicalization::Simple);
    let signed = sample_message().sign(&key, &params).expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    let refolded = raw.replace("Subject: Ihre Rechnung", "SUBJECT: Ihre Rechnung");
    assert!(dkim::verify(&refolded, &key.verifying_key()).is_err());
}

#[test]
fn signing_is_deterministic_and_timestamped_on_request() {
    let key = SigningKey::from_ed25519_seed(&[3u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("params")
        .timestamp(1_700_000_000);
    let first = sample_message().sign(&key, &params).expect("sign");
    let second = sample_message().sign(&key, &params).expect("sign");
    assert_eq!(first, second);
    let raw = String::from_utf8(first).expect("utf-8");
    assert!(raw.contains(" t=1700000000;"));
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn duplicate_and_preserved_headers_are_all_signed() {
    let mut message = sample_message();
    message
        .push_header(Header::new("X-Trace", "one").expect("header"))
        .expect("push");
    message
        .push_header(Header::new("X-Trace", "two").expect("header"))
        .expect("push");
    let key = SigningKey::from_ed25519_seed(&[17u8; 32]);
    let signed = message
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    // The `h=` tag may be folded between its names; read it through the parser
    // so the inserted FWS does not matter.
    let signature = &dkim::signatures(&raw).expect("signature")[0];
    assert_eq!(
        signature.signed_headers,
        [
            "from",
            "to",
            "subject",
            "date",
            "message-id",
            "x-trace",
            "x-trace",
            "mime-version",
            "content-type",
            "content-transfer-encoding"
        ]
    );
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());

    // Removing one of the duplicated headers must break the signature.
    let removed = raw.replace("X-Trace: one\r\n", "");
    assert!(dkim::verify(&removed, &key.verifying_key()).is_err());

    // Appending another one must break it too (both occurrences are covered).
    let appended = raw.replace("X-Trace: two\r\n", "X-Trace: two\r\nX-Trace: three\r\n");
    assert!(dkim::verify(&appended, &key.verifying_key()).is_err());
}

#[test]
fn bcc_recipients_are_not_signed_because_they_are_not_sent() {
    let key = SigningKey::from_ed25519_seed(&[19u8; 32]);
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .bcc("secret@example.com")
        .expect("bcc")
        .body("hi")
        .build()
        .expect("build");
    let signed = message
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(!raw.contains("secret@example.com"));
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn html_with_inline_parts_signs_and_verifies() {
    let key = SigningKey::from_ed25519_seed(&[23u8; 32]);
    let message = Message::builder()
        .from("a@example.com")
        .expect("from")
        .to("b@example.com")
        .expect("to")
        .body("hi")
        .html_body("<img src=\"cid:logo\">")
        .attachment(
            Attachment::new("logo.png", "image/png", vec![0x89, b'P', b'N', b'G'])
                .with_content_id("logo")
                .expect("valid content id"),
        )
        .build()
        .expect("build");
    let signed = message
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn explicit_header_list_always_covers_from() {
    let key = SigningKey::from_ed25519_seed(&[29u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("params")
        .signed_headers(["Subject"])
        .expect("signed headers");
    let signed = sample_message().sign(&key, &params).expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(raw.contains("h=from:subject;"));
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

/// A message with hundreds of header occurrences builds an `h=` tag far longer
/// than one line. Every emitted `DKIM-Signature` line must stay under the
/// 78-column recommendation (RFC 5322 §2.1.1), and the signature must still
/// verify after folding inside the tag.
#[test]
fn a_four_hundred_header_message_folds_every_dkim_line_under_78_columns() {
    let key = SigningKey::from_ed25519_seed(&[31u8; 32]);
    let mut message = sample_message();
    for index in 0..400 {
        message
            .push_header(Header::new("X-Received-Chain", format!("{index}")).expect("header"))
            .expect("push header");
    }
    let signed = message
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");

    let (head, _) = raw.split_once("\r\n\r\n").expect("header/body split");
    let signature: String = {
        let mut lines = head.split("\r\n");
        let mut collected = vec![lines.next().expect("first line")];
        for line in lines {
            if !line.starts_with(' ') && !line.starts_with('\t') {
                break;
            }
            collected.push(line);
        }
        collected.join("\r\n")
    };
    assert!(
        signature.contains("h="),
        "the signature must carry an h= tag"
    );
    for line in signature.split("\r\n") {
        assert!(
            line.len() <= 78,
            "DKIM-Signature line of {} columns: {line:?}",
            line.len()
        );
    }
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

// ---------------------------------------------------------------------------
// Failure surface
// ---------------------------------------------------------------------------

#[test]
fn unsigned_message_has_no_signature() {
    let key = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("record");
    assert_eq!(
        dkim::verify("From: a@example.com\r\n\r\nhi", &key).unwrap_err(),
        Error::MissingSignature
    );
}

#[test]
fn a_signature_with_another_algorithm_is_reported_as_unmatched() {
    let rsa_key = VerifyingKey::from_dns_record(RFC8463_RSA_RECORD).expect("record");
    let ed_only = RFC8463_MESSAGE
        .split("DKIM-Signature: v=1; a=rsa-sha256")
        .next()
        .expect("split");
    assert_eq!(
        dkim::verify(ed_only, &rsa_key).unwrap_err(),
        Error::NoMatchingSignature
    );
}

#[test]
fn malformed_signatures_are_rejected_with_a_typed_error() {
    let key = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("record");
    let cases = [
        "DKIM-Signature: v=2; a=ed25519-sha256; d=e; s=s; h=from; bh=AA==; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=rsa-sha1; d=e; s=s; h=from; bh=AA==; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; c=weird/relaxed; d=e; s=s; h=from; bh=AA==; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; bh=AA==; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=to; bh=AA==; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=from; bh=!!; b=AA==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=from; bh=AA==; b=AA==; b=BB==\r\nFrom: a@b\r\n\r\nx",
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=from; bh=AA==; b=AA==; t=soon\r\nFrom: a@b\r\n\r\nx",
    ];
    for case in cases {
        let outcome = dkim::verify(case, &key);
        assert!(
            matches!(
                outcome,
                Err(Error::InvalidSignature(_) | Error::InvalidSignatureCause { .. })
            ),
            "expected InvalidSignature, got {outcome:?} for {case:?}"
        );
    }
}

#[test]
fn malformed_signature_causes_reach_error_source() {
    let bad_base64 = concat!(
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=from; bh=!!; b=AA==\r\n",
        "From: a@b\r\n",
        "\r\n",
        "x",
    );
    let error = dkim::signatures(bad_base64).unwrap_err();
    let Error::InvalidSignatureCause { source, .. } = &error else {
        panic!("base64 failure must keep a typed cause: {error:?}");
    };
    assert!(matches!(
        source.as_ref(),
        SignatureCause::Base64 { tag: "bh=", .. }
    ));
    let cause = std::error::Error::source(&error).expect("SignatureCause is the first source");
    assert!(cause.to_string().contains("bh= is not base64"));
    let leaf = std::error::Error::source(cause).expect("base64 decoder error is the next source");
    assert!(
        leaf.to_string().contains("Invalid symbol"),
        "leaf was {leaf}"
    );

    let duplicate = concat!(
        "DKIM-Signature: v=1; a=ed25519-sha256; d=e; s=s; h=from; bh=AA==; b=AA==; b=BB==\r\n",
        "From: a@b\r\n",
        "\r\n",
        "x",
    );
    let error = dkim::signatures(duplicate).unwrap_err();
    let Error::InvalidSignatureCause { source, .. } = &error else {
        panic!("tag-list failure must keep a typed cause: {error:?}");
    };
    assert!(matches!(
        source.as_ref(),
        SignatureCause::Defect(SignatureDefect::DuplicateTag { name }) if name == "b"
    ));
    let cause = std::error::Error::source(&error).expect("SignatureCause is the first source");
    assert!(cause.to_string().contains("duplicate b= tag"));
}

#[test]
fn invalid_base64_keeps_the_decoder_error_as_source() {
    let error = mime_message::transfer::decode_base64("SGVsbG8*").unwrap_err();
    let Error::InvalidBase64 { part, offset, .. } = &error else {
        panic!("expected InvalidBase64: {error:?}");
    };
    assert_eq!((*part, *offset), (0, 7));
    let source = std::error::Error::source(&error).expect("decoder error is the source");
    assert!(
        source.to_string().contains("Invalid symbol"),
        "source was {source}"
    );
}

#[test]
fn malformed_keys_are_rejected_without_leaking_material() {
    let bad_pems = [
        "not a key",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
    ];
    for pem in bad_pems {
        let error = SigningKey::from_pem(pem).unwrap_err();
        // Only the labels this crate claims reach the PKCS decoder, and only those can
        // fail with a typed cause; any other label, and text without a BEGIN line, is
        // rejected by our own check and stays a plain InvalidKey.
        let claimed = ["RSA PRIVATE KEY", "PRIVATE KEY"]
            .iter()
            .any(|label| pem.contains(&format!("-----BEGIN {label}-----")));
        if claimed {
            assert!(
                matches!(error, Error::InvalidKeyPem(_)),
                "{pem:?} -> {error:?}"
            );
            assert!(
                std::error::Error::source(&error).is_some(),
                "a typed cause must carry the parser error: {error:?}"
            );
        } else {
            assert!(
                matches!(error, Error::InvalidKey(_)),
                "{pem:?} -> {error:?}"
            );
        }
        let text = format!("{error:?}");
        assert!(!text.contains("AAAA"), "error leaked key bytes: {text}");
    }

    let small = fixture("rsa-small.pem");
    match SigningKey::from_pem(&small) {
        Err(Error::InvalidKey(reason)) => assert_eq!(
            reason,
            KeyRejected::BelowMinimumBits {
                bits: 512,
                minimum: 1024,
            },
            "a 512-bit key must be classified with the bits it has"
        ),
        other => panic!("a 512-bit key must be rejected, got {other:?}"),
    }

    let records = [
        "",
        "v=DKIM1;",
        "v=DKIM1; k=rsa; p=",
        "v=DKIM1; k=ed25519; p=AAAA",
        "v=DKIM1; k=rsa; p=AAAA",
        "v=DKIM1; k=dsa; p=AAAA",
        "v=DKIM2; k=ed25519; p=AAAA",
        "v=DKIM1; p",
    ];
    for record in records {
        let outcome = VerifyingKey::from_dns_record(record);
        assert!(
            matches!(outcome, Err(Error::InvalidKey(_))),
            "{record:?} -> {outcome:?}"
        );
    }
}

#[test]
fn a_key_of_the_wrong_type_cannot_verify() {
    let rsa = VerifyingKey::from_dns_record(RFC8463_RSA_RECORD).expect("record");
    let ed = SigningKey::from_ed25519_seed(&[31u8; 32]);
    let signed = sample_message()
        .sign(&ed, &SignParams::new("example.com", "sel").expect("params"))
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert_eq!(
        dkim::verify(&raw, &rsa).unwrap_err(),
        Error::NoMatchingSignature
    );
}

#[test]
fn a_modified_signature_is_rejected() {
    let key = SigningKey::from_ed25519_seed(&[37u8; 32]);
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    // Flip one base64 character of the b= value.
    let marker = "b=";
    let start = raw.find(marker).expect("b= tag") + marker.len();
    let mut bytes = raw.clone().into_bytes();
    bytes[start] = if bytes[start] == b'A' { b'B' } else { b'A' };
    let modified = String::from_utf8(bytes).expect("utf-8");
    assert!(dkim::verify(&modified, &key.verifying_key()).is_err());
}

#[test]
fn signatures_of_a_message_are_listed_in_order() {
    let ed = SigningKey::from_ed25519_seed(&[41u8; 32]);
    let mut raw = String::from_utf8(
        sample_message()
            .sign(&ed, &SignParams::new("example.com", "one").expect("params"))
            .expect("sign"),
    )
    .expect("utf-8");
    // Sign the already signed message again: two DKIM-Signature fields.
    let re_signed = Message::parse(&raw)
        .expect("parse")
        .sign(&ed, &SignParams::new("example.com", "two").expect("params"));
    raw = String::from_utf8(re_signed.expect("sign")).expect("utf-8");
    let headers = dkim::signatures(&raw).expect("signatures");
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].selector, "two");
    assert_eq!(headers[1].selector, "one");
    // Both verify.
    assert!(dkim::verify(&raw, &ed.verifying_key()).is_ok());
}

#[test]
fn ed25519_pkcs8_pem_is_accepted() {
    let pem = fixture("ed25519-private.pem");
    let key = SigningKey::from_pem(&pem).expect("ed25519 pkcs8");
    assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
    // It is the RFC 8463 key.
    assert_eq!(
        key.dns_record(),
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    );
}

#[test]
fn ed25519_seed_base64_errors_are_typed() {
    assert!(matches!(
        SigningKey::from_ed25519_seed_base64("!!!"),
        Err(Error::InvalidKey(_))
    ));
    assert!(matches!(
        SigningKey::from_ed25519_seed_base64("AAAA"),
        Err(Error::InvalidKey(_))
    ));
}

#[test]
fn signing_keys_do_not_print_their_material() {
    let key = rsa_signing_key();
    let text = format!("{key:?}");
    assert!(text.contains("RsaSha256"));
    assert!(!text.contains("PRIVATE"));
    assert!(text.len() < 200, "Debug output is too large: {text}");
}

#[test]
fn dkim_is_send_sync_and_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SigningKey>();
    assert_send_sync::<VerifyingKey>();
    assert_send_sync::<SignParams>();
    assert_send_sync::<dkim::SignatureHeader>();

    let key = std::sync::Arc::new(SigningKey::from_ed25519_seed(&[43u8; 32]));
    let public = std::sync::Arc::new(key.verifying_key());
    let mut handles = Vec::new();
    for _ in 0..16 {
        let key = std::sync::Arc::clone(&key);
        let public = std::sync::Arc::clone(&public);
        handles.push(std::thread::spawn(move || {
            for _ in 0..8 {
                let signed = sample_message()
                    .sign(
                        &key,
                        &SignParams::new("example.com", "sel").expect("params"),
                    )
                    .expect("sign");
                let raw = String::from_utf8(signed).expect("utf-8");
                dkim::verify(&raw, &public).expect("verify");
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
}

// ---------------------------------------------------------------------------
// Key formats
// ---------------------------------------------------------------------------

#[test]
fn a_pkcs8_rsa_pem_is_accepted() {
    let key = SigningKey::from_pem(&fixture("rsa-private-pkcs8.pem")).expect("pkcs8");
    assert_eq!(key.algorithm().as_str(), "rsa-sha256");
    // Signing with it works end to end.
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "pkcs8").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn an_rsa_public_key_pem_reads_and_rejects_small_keys() {
    let key = VerifyingKey::from_public_key_pem(&fixture("rsa-public.pem")).expect("public");
    assert_eq!(key.algorithm().as_str(), "rsa-sha256");
    match VerifyingKey::from_public_key_pem(&fixture("rsa-small-public.pem")) {
        Err(Error::InvalidKey(reason)) => assert_eq!(
            reason,
            KeyRejected::BelowMinimumBits {
                bits: 512,
                minimum: 1024,
            }
        ),
        other => panic!("512-bit key must be rejected: {other:?}"),
    }
    assert!(matches!(
        VerifyingKey::from_public_key_pem(
            "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"
        ),
        Err(Error::InvalidKey(_))
    ));
}

#[test]
fn a_dns_record_round_trips_through_the_signing_key() {
    let key = rsa_signing_key();
    let record = key.dns_record();
    assert!(record.starts_with("v=DKIM1; k=rsa; p="));
    let parsed = VerifyingKey::from_dns_record(&record).expect("record");
    assert_eq!(parsed.algorithm(), key.algorithm());

    // The same DER straight from the record, and the raw Ed25519 bytes.
    let der = base64_decode_p(record.split("p=").nth(1).expect("p="));
    assert!(VerifyingKey::rsa_from_der(&der).is_ok());
    assert!(VerifyingKey::from_dns_record("v=DKIM1; p=").is_err());
}

fn base64_decode_p(value: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(value.trim()).expect("base64")
}

#[test]
fn a_small_rsa_key_in_a_record_is_rejected() {
    let pem = fixture("rsa-small-public.pem");
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let record = format!("v=DKIM1; k=rsa; p={}", body.replace(['\n', '\r'], ""));
    match VerifyingKey::from_dns_record(&record) {
        Err(Error::InvalidKey(reason)) => assert_eq!(
            reason,
            KeyRejected::BelowMinimumBits {
                bits: 512,
                minimum: 1024,
            }
        ),
        other => panic!("512-bit record must be rejected: {other:?}"),
    }
}

#[test]
fn identity_and_other_tags_survive_the_round_trip() {
    let key = SigningKey::from_ed25519_seed(&[73u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@example.com")
        .expect("identity")
        .timestamp(1_700_000_001);
    let signed = sample_message().sign(&key, &params).expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(raw.contains(" i=@example.com;"));
    let header = &dkim::signatures(&raw).expect("signatures")[0];
    assert_eq!(header.identity.as_deref(), Some("@example.com"));
    assert_eq!(header.timestamp, Some(1_700_000_001));
    assert_eq!(header.body_length, None);
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn identity_domain_must_be_d_or_a_subdomain_of_d() {
    let key = SigningKey::from_ed25519_seed(&[74u8; 32]);
    let public = key.verifying_key();

    let exact = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@example.com")
        .expect("identity");
    let raw = String::from_utf8(sample_message().sign(&key, &exact).expect("sign")).expect("utf-8");
    assert!(dkim::verify(&raw, &public).is_ok());

    let subdomain = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@mail.example.com")
        .expect("identity");
    let raw =
        String::from_utf8(sample_message().sign(&key, &subdomain).expect("sign")).expect("utf-8");
    assert!(dkim::verify(&raw, &public).is_ok());

    let sibling_suffix = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@badexample.com")
        .expect("identity");
    let raw = String::from_utf8(sample_message().sign(&key, &sibling_suffix).expect("sign"))
        .expect("utf-8");
    assert_eq!(
        dkim::verify(&raw, &public).unwrap_err(),
        Error::InvalidSignature("i= domain is not d= or a subdomain".to_string())
    );

    let outside = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@evil.example")
        .expect("identity");
    let raw =
        String::from_utf8(sample_message().sign(&key, &outside).expect("sign")).expect("utf-8");
    assert_eq!(
        dkim::verify(&raw, &public).unwrap_err(),
        Error::InvalidSignature("i= domain is not d= or a subdomain".to_string())
    );

    let shorter = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@com")
        .expect("identity");
    let raw =
        String::from_utf8(sample_message().sign(&key, &shorter).expect("sign")).expect("utf-8");
    assert_eq!(
        dkim::verify(&raw, &public).unwrap_err(),
        Error::InvalidSignature("i= domain is not d= or a subdomain".to_string())
    );

    let malformed = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@")
        .expect("identity");
    let raw =
        String::from_utf8(sample_message().sign(&key, &malformed).expect("sign")).expect("utf-8");
    assert_eq!(
        dkim::verify(&raw, &public).unwrap_err(),
        Error::InvalidSignature("i= identity is not local@domain".to_string())
    );
}

#[test]
fn multiple_from_headers_are_rejected_before_verification() {
    let key = SigningKey::from_ed25519_seed(&[75u8; 32]);
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "sel").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());

    let forged = format!("From: forged@example.net\r\n{raw}");
    assert_eq!(
        dkim::verify(&forged, &key.verifying_key()).unwrap_err(),
        Error::InvalidSignature("message contains multiple From header fields".to_string())
    );
}

#[test]
fn dkim_parameters_reject_header_injection() {
    let key = SigningKey::from_ed25519_seed(&[79u8; 32]);
    let message = sample_message();

    let domain = SignParams::new("example.com\r\nBcc: attacker@example.com", "sel").unwrap_err();
    assert_eq!(domain, Error::HeaderInjection("DKIM domain"));
    let empty_domain = SignParams::new("", "sel").unwrap_err();
    assert_eq!(empty_domain, Error::EmptyHeader("DKIM domain"));

    let selector = SignParams::new("example.com", "sel; x=y").unwrap_err();
    assert_eq!(selector, Error::HeaderInjection("DKIM selector"));
    let empty_selector = SignParams::new("example.com", "").unwrap_err();
    assert_eq!(empty_selector, Error::EmptyHeader("DKIM selector"));

    let identity = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@example.com\r\nBcc: attacker@example.com")
        .unwrap_err();
    assert_eq!(identity, Error::HeaderInjection("DKIM identity"));

    let signed_header = SignParams::new("example.com", "sel")
        .expect("params")
        .signed_headers(["Subject", "X-Bad:Injected"])
        .unwrap_err();
    assert_eq!(signed_header, Error::HeaderInjection("DKIM signed header"));

    let folded_header = SignParams::new("example.com", "sel")
        .expect("params")
        .signed_headers([" Subject\r\n"])
        .unwrap_err();
    assert_eq!(folded_header, Error::HeaderInjection("DKIM signed header"));

    let null = SignParams::new("example.com", "sel")
        .expect("params")
        .identity("@example.com\0")
        .unwrap_err();
    assert_eq!(null, Error::HeaderInjection("DKIM identity"));

    let mut mutated = SignParams::new("example.com", "sel").expect("params");
    mutated.domain = "example.com\r\nBcc: attacker@example.com".to_string();
    assert_eq!(
        message.sign(&key, &mutated).unwrap_err(),
        Error::HeaderInjection("DKIM domain")
    );

    let mut mutated = SignParams::new("example.com", "sel").expect("params");
    mutated.signed_headers = Some(vec!["Subject:Injected".to_string()]);
    assert_eq!(
        message.sign(&key, &mutated).unwrap_err(),
        Error::HeaderInjection("DKIM signed header")
    );
}

#[test]
fn dkim_parameters_accept_normal_values() {
    let key = SigningKey::from_ed25519_seed(&[83u8; 32]);
    let params = SignParams::new("example.com", "sel")
        .expect("domain and selector")
        .identity("@example.com")
        .expect("identity")
        .signed_headers(["Subject", "Message-ID"])
        .expect("signed headers");
    let signed = sample_message().sign(&key, &params).expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    let signature = &dkim::signatures(&raw).expect("signatures")[0];
    assert_eq!(signature.domain, "example.com");
    assert_eq!(signature.selector, "sel");
    assert_eq!(signature.identity.as_deref(), Some("@example.com"));
    assert!(signature
        .signed_headers
        .iter()
        .any(|name| name == "subject"));
    assert!(dkim::verify(&raw, &key.verifying_key()).is_ok());
}

#[test]
fn body_length_and_unknown_tags_are_parsed() {
    let raw = concat!(
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel;\r\n",
        " h=from; bh=AA==; b=AA==; l=42; q=dns/txt; n=notes\r\n",
        "From: a@example.com\r\n",
        "\r\n",
        "x",
    );
    let header = &dkim::signatures(raw).expect("signatures")[0];
    assert_eq!(header.body_length, Some(42));

    let bad = raw.replace("l=42", "l=many");
    assert!(matches!(
        dkim::signatures(&bad),
        Err(Error::InvalidSignature(_) | Error::InvalidSignatureCause { .. })
    ));
}

#[test]
fn a_broken_h_tag_is_rejected() {
    let raw = concat!(
        "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=sel;\r\n",
        " h=:; bh=AA==; b=AA==\r\n",
        "From: a@example.com\r\n",
        "\r\n",
        "x",
    );
    assert!(matches!(
        dkim::signatures(raw),
        Err(Error::InvalidSignature(_) | Error::InvalidSignatureCause { .. })
    ));
}

#[test]
fn signatures_of_the_wrong_length_are_malformed() {
    let rsa = VerifyingKey::from_dns_record(RFC8463_RSA_RECORD).expect("record");
    let rsa_message = concat!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel;\r\n",
        " h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=AAAA\r\n",
        "From: a@example.com\r\n",
        "\r\n",
        "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n",
    );
    // RSA signatures are length-checked by the verifier and fail closed.
    assert!(dkim::verify(rsa_message, &rsa).is_err());

    let ed = VerifyingKey::from_dns_record(RFC8463_ED25519_RECORD).expect("record");
    let ed_message = rsa_message.replace("a=rsa-sha256", "a=ed25519-sha256");
    let outcome = dkim::verify(&ed_message, &ed);
    assert!(
        matches!(
            outcome,
            Err(Error::InvalidSignature(_) | Error::InvalidSignatureCause { .. })
        ),
        "got {outcome:?}"
    );
}

#[test]
fn a_broken_signature_does_not_hide_a_good_one() {
    let key = SigningKey::from_ed25519_seed(&[47u8; 32]);
    let signed = sample_message()
        .sign(
            &key,
            &SignParams::new("example.com", "good").expect("params"),
        )
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    // Prepend a signature that cannot even be parsed (no h= tag).
    let broken = format!("DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=broken\r\n{raw}");
    assert_eq!(
        dkim::signatures(&broken).unwrap_err(),
        Error::InvalidSignature("missing h= tag".to_string())
    );
    // …but verification still finds the good one.
    let verified = dkim::verify(&broken, &key.verifying_key()).expect("good signature");
    assert_eq!(verified.selector, "good");
}

#[test]
fn a_malformed_signature_does_not_hide_a_matching_mismatch() {
    let key = SigningKey::from_ed25519_seed(&[49u8; 32]);
    let signed = sample_message()
        .sign(&key, &SignParams::new("example.com", "good").unwrap())
        .expect("sign");
    let raw = String::from_utf8(signed).expect("utf-8");
    let tampered = raw.replace("Anbei die Rechnung.", "Anbei die Rechnung?");
    let broken =
        format!("DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=broken\r\n{tampered}");

    assert_eq!(
        dkim::verify(&broken, &key.verifying_key()).unwrap_err(),
        Error::BodyHashMismatch {
            domain: "example.com".to_string(),
            selector: "good".to_string(),
        }
    );
}

/// Both PEM entry points bound their input at 64 KiB (`MAX_PEM_BYTES` in
/// `src/dkim.rs`) *before* any PEM, base64 or big-integer work starts. The
/// boundary is `>`, not `>=`: a real key padded to exactly the limit still
/// parses, one byte more is refused with `LimitExceeded`, and a megabyte of
/// padding costs a length check instead of a decode. Padding goes *before* the
/// `BEGIN` line because the PEM parsers reject trailing bytes but accept a
/// preamble, which is also why the byte count is the right thing to bound.
#[test]
fn pem_input_is_bounded_before_any_decoder_runs() {
    const MAX: usize = 64 * 1024;

    let rsa = fixture("rsa-private.pem");
    let pad = MAX - rsa.len() - 1;
    let preamble = format!("#{}\n", "p".repeat(pad - 1));
    let at_limit = format!("{preamble}{rsa}");
    assert_eq!(at_limit.len(), MAX, "the probe has to land on the bound");
    assert!(
        SigningKey::from_pem(&at_limit).is_ok(),
        "a key padded to exactly the limit must still parse"
    );

    let over = format!("#{at_limit}");
    let error = SigningKey::from_pem(&over).unwrap_err();
    assert_eq!(
        error,
        Error::LimitExceeded {
            what: "PEM key size in bytes",
            limit: MAX,
        }
    );
    // The error names the bound, never key material.
    assert!(!format!("{error:?}").contains("-----BEGIN"));

    // The public-key entry point carries the same bound.
    let oversized = format!("{}{}", fixture("rsa-public.pem"), "A".repeat(1024 * 1024));
    assert!(matches!(
        VerifyingKey::from_public_key_pem(&oversized),
        Err(Error::LimitExceeded { limit, .. }) if limit == MAX
    ));
}
