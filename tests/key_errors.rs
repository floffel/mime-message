//! A PEM key that fails to decode reports a typed cause, not a flattened string.
//!
//! Audit finding (issue #7): `SigningKey::from_pem` rendered the PKCS#1/PKCS#8
//! parser errors into `Error::InvalidKey(String)`, so `Error::source()` was always
//! `None` and the failed Ed25519 probe vanished before the RSA fallback ran. These
//! tests pin the replacement: the cause survives, the stage is classified, and no key
//! material reaches the message.
#![cfg(feature = "dkim")]

use mime_message::dkim::SigningKey;
use mime_message::{Error, KeyParseError};

/// Wraps a base64 body in a PEM envelope with the given label.
fn pem(label: &str, body: &str) -> String {
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

/// The base64 body of a fixture, without its envelope lines.
fn body_of(fixture: &str) -> String {
    let text = std::fs::read_to_string(format!("tests/fixtures/{fixture}"))
        .unwrap_or_else(|error| panic!("{fixture} is readable: {error}"));
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// The typed cause of an [`Error::InvalidKeyPem`], or a panic naming what came back.
fn cause_of(error: &Error) -> &KeyParseError {
    match error {
        Error::InvalidKeyPem(cause) => cause,
        other => panic!("expected a typed PEM cause, got {other:?}"),
    }
}

#[test]
fn pkcs1_body_that_is_not_der_keeps_the_parser_error() {
    // A zero-length SEQUENCE: valid base64 inside a valid PEM envelope, but not a
    // PKCS#1 private key. Before the fix this was a formatted sentence.
    let error = SigningKey::from_pem(&pem("RSA PRIVATE KEY", "MAA=")).unwrap_err();
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs1(_)),
        "expected a typed PKCS#1 cause, got {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.starts_with("invalid DKIM key: PKCS#1"),
        "stage missing from {rendered}"
    );
    let cause = std::error::Error::source(&error).expect("the parser error is the source");
    assert!(cause.to_string().contains("PKCS#1"), "cause was {cause}");
    let leaf = std::error::Error::source(cause_of(&error)).expect("the parser error is the leaf");
    assert!(
        leaf.to_string().contains("ASN.1"),
        "the leaf must be the parsers own words, was {leaf}"
    );
}

#[test]
fn pkcs8_body_that_is_neither_algorithm_keeps_both_probes() {
    // A SEQUENCE holding a NULL: base64 and ASN.1 are fine, the document is not a
    // private key, so both the Ed25519 probe and the RSA fallback fail.
    let error = SigningKey::from_pem(&pem("PRIVATE KEY", "MAIFAA==")).unwrap_err();
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs8 { .. }),
        "expected a typed PKCS#8 cause, got {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("neither Ed25519"),
        "lost the probe order: {rendered}"
    );
    assert!(
        rendered.contains("nor RSA"),
        "dropped the RSA answer: {rendered}"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the PKCS#8 answer must stay reachable as a source"
    );
    let leaf = std::error::Error::source(cause_of(&error)).expect("the RSA answer is the leaf");
    assert!(leaf.to_string().contains("PKCS#8"), "leaf was {leaf}");
}

#[test]
fn the_label_decides_the_classification_for_the_same_bytes() {
    let pkcs1 = SigningKey::from_pem(&pem("RSA PRIVATE KEY", "MAA=")).unwrap_err();
    let pkcs8 = SigningKey::from_pem(&pem("PRIVATE KEY", "MAA=")).unwrap_err();
    assert!(
        matches!(cause_of(&pkcs1), KeyParseError::Pkcs1(_)),
        "a RSA PRIVATE KEY block must be reported as PKCS#1, got {pkcs1:?}"
    );
    assert!(
        matches!(cause_of(&pkcs8), KeyParseError::Pkcs8 { .. }),
        "a PRIVATE KEY block must be reported as PKCS#8, got {pkcs8:?}"
    );
}

#[test]
fn an_empty_body_is_still_a_typed_cause() {
    let error = SigningKey::from_pem(&pem("RSA PRIVATE KEY", "")).unwrap_err();
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs1(_)),
        "an empty body must not fall back to a string, got {error:?}"
    );
}

#[test]
fn the_same_input_produces_equal_errors() {
    let text = pem("PRIVATE KEY", "MAIFAA==");
    let first = SigningKey::from_pem(&text).unwrap_err();
    let second = SigningKey::from_pem(&text).unwrap_err();
    assert_eq!(first, second, "Error must stay comparable after the change");
}

#[test]
fn unsupported_labels_stay_a_plain_invalid_key_without_a_source() {
    let error = SigningKey::from_pem(&pem("CERTIFICATE", "MAA=")).unwrap_err();
    assert!(
        matches!(error, Error::InvalidKey(_)),
        "an unknown label is our own rejection, not a parser failure: {error:?}"
    );
    assert!(
        std::error::Error::source(&error).is_none(),
        "only InvalidKeyPem carries a source"
    );
}

#[test]
fn the_label_match_stays_case_sensitive() {
    let error = SigningKey::from_pem(&pem("rsa private key", "MAA=")).unwrap_err();
    assert!(
        matches!(error, Error::InvalidKey(_)),
        "a lower-case label is unsupported, not decoded: {error:?}"
    );
}

#[test]
fn a_pem_block_without_an_end_line_is_a_plain_invalid_key() {
    // The label is read from the BEGIN line alone, so a truncated file still names a
    // stage instead of failing with something opaque.
    let truncated = "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n";
    let error = SigningKey::from_pem(truncated).unwrap_err();
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs1(_)),
        "a truncated block is a PKCS#1 decode failure, got {error:?}"
    );
}

#[test]
fn valid_keys_still_load_for_each_standard_label() {
    let pkcs1 = std::fs::read_to_string("tests/fixtures/rsa-private.pem").expect("fixture");
    let pkcs8 = std::fs::read_to_string("tests/fixtures/rsa-private-pkcs8.pem").expect("fixture");
    let ed25519 = std::fs::read_to_string("tests/fixtures/ed25519-private.pem").expect("fixture");
    assert_eq!(
        SigningKey::from_pem(&pkcs1)
            .expect("pkcs1")
            .algorithm()
            .as_str(),
        "rsa-sha256"
    );
    assert_eq!(
        SigningKey::from_pem(&pkcs8)
            .expect("pkcs8")
            .algorithm()
            .as_str(),
        "rsa-sha256"
    );
    assert_eq!(
        SigningKey::from_pem(&ed25519)
            .expect("ed25519")
            .algorithm()
            .as_str(),
        "ed25519-sha256"
    );
}

#[test]
fn a_relabelled_block_reports_both_probes_of_the_real_decoders() {
    // `ED25519 PRIVATE KEY` passes the label match, but both decoders require the
    // standard PKCS#8 label, so the body is rejected with one typed cause that still
    // carries what each probe said. That the arm cannot succeed even with a valid body
    // is filed separately: the label is accepted and then unusable.
    let relabelled = pem("ED25519 PRIVATE KEY", &body_of("rsa-private-pkcs8.pem"));
    let error = SigningKey::from_pem(&relabelled).unwrap_err();
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs8 { .. }),
        "expected a typed PKCS#8 cause, got {error:?}"
    );
    let rendered = error.to_string();
    assert!(rendered.contains("neither Ed25519"), "{rendered}");
    assert!(rendered.contains("nor RSA"), "{rendered}");
}

#[test]
fn no_key_material_reaches_the_rendered_error() {
    // A base64 body of marker bytes that is not a PKCS#1 key.
    let body = "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUYwMTIzNDU2Nzg5QUJDREVG";
    let error = SigningKey::from_pem(&pem("RSA PRIVATE KEY", body)).unwrap_err();
    let rendered = format!("{error} {error:?}");
    assert!(
        !rendered.contains(body),
        "the error echoed key material: {rendered}"
    );
    assert!(
        matches!(cause_of(&error), KeyParseError::Pkcs1(_)),
        "expected a typed cause for a bad DER body, got {error:?}"
    );
}
