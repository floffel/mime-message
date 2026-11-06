//! "The message never contains key material" is a property of the type.
//!
//! Audit finding (issue #37): the variant that reports an unusable DKIM key was a
//! bare `String` with derived `Debug` and `Display`, so the documented guarantee held
//! only as long as every call site remembered it — and the call sites interpolated
//! third-party error text the library does not control. These tests pin the
//! replacement: `Error::InvalidKey` carries a closed [`KeyRejected`] reason whose
//! fields are byte counts and crate constants, so there is no field into which a PEM
//! body, a seed or a DNS `p=` value could be written.
//!
//! Each rejection is also checked end to end with key-shaped input, and every length
//! and bit limit it reports is pinned at its boundary.
#![cfg(feature = "dkim")]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mime_message::dkim::{SigningKey, VerifyingKey};
use mime_message::{Error, KeyRejected};

/// A base64 payload of 140 characters: long enough that a leak into an error message
/// is unmistakable, and pure base64 alphabet so a run of it is what a key looks like.
fn marker() -> String {
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(4)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/{name}"))
        .unwrap_or_else(|error| panic!("{name} is readable: {error}"))
}

/// Wraps a body in a PEM envelope with the given label.
fn pem(label: &str, body: &str) -> String {
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

/// Fails when `text` carries anything that could be key material.
///
/// Three blunt checks, because a redaction test must not be cleverer than the leak it
/// looks for: no PEM marker, no type label, and no run of 100+ base64 characters.
fn assert_no_key_material(text: &str) {
    assert!(
        !text.contains("BEGIN"),
        "a PEM marker reached the error: {text}"
    );
    assert!(
        !text.contains("PRIVATE"),
        "a key label reached the error: {text}"
    );
    let longest = text
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=')))
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(
        longest < 100,
        "a {longest}-character base64 run reached the error: {text}"
    );
}

/// `Display`, `Debug` and the whole source chain of one error, as a log line would
/// render it.
fn rendered(error: &Error) -> String {
    use std::fmt::Write as _;

    let mut text = format!("{error} {error:?}");
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(cause) = cursor {
        // Writing into a `String` cannot fail.
        let _ = write!(text, " {cause}");
        cursor = std::error::Error::source(cause);
    }
    text
}

/// Every reason the enum can carry, so the rendering test cannot silently skip one
/// when a variant is added.
fn every_reason() -> Vec<KeyRejected> {
    vec![
        KeyRejected::NotPem,
        KeyRejected::UnsupportedPemLabel,
        KeyRejected::NotBase64 { what: "p=" },
        KeyRejected::WrongLength {
            what: "Ed25519 seed",
            expected: 32,
            found: 31,
        },
        KeyRejected::BelowMinimumBits {
            bits: 512,
            minimum: 1024,
        },
        KeyRejected::TagWithoutEquals,
        KeyRejected::EmptyTagName,
        KeyRejected::DuplicateTag,
        KeyRejected::UnsupportedRecordVersion,
        KeyRejected::MissingPublicKey,
        KeyRejected::RevokedKey,
        KeyRejected::UnsupportedKeyType,
        KeyRejected::InvalidRsaPublicKey,
        KeyRejected::InvalidEd25519PublicKey,
    ]
}

#[test]
fn every_reason_renders_fixed_text_and_nothing_else() {
    for reason in every_reason() {
        let display = reason.to_string();
        let debug = format!("{reason:?}");
        assert!(!display.is_empty(), "{debug} must render a reason");
        assert!(
            display.len() < 120,
            "the reason text must be fixed, not grown from input: {display}"
        );
        // The type itself is the boundary: neither direction can carry bytes.
        assert_no_key_material(&format!("{display} {debug}"));
        // A reason is Copy + Eq, so it can be matched and compared in tests and in
        // downstream code without allocating.
        assert_eq!(reason, reason, "{debug} must stay comparable");
    }
}

#[test]
fn no_reason_reports_a_source() {
    for reason in every_reason() {
        let error = Error::InvalidKey(reason);
        assert!(
            std::error::Error::source(&error).is_none(),
            "{reason:?} must not invent a cause: {error:?}"
        );
    }
}

#[test]
fn pem_rejections_never_echo_the_input() {
    let body = marker();

    let error = SigningKey::from_pem(&body).unwrap_err();
    assert_eq!(error, Error::InvalidKey(KeyRejected::NotPem));
    assert_no_key_material(&rendered(&error));

    // A BEGIN line alone is not a complete block, so the PEM parser reports
    // "not PEM" without exposing the label or body.
    let error = SigningKey::from_pem("-----BEGIN RSA PRIVATE KEY-----\nMAA=\n").unwrap_err();
    assert_eq!(error, Error::InvalidKey(KeyRejected::NotPem));
    assert_no_key_material(&rendered(&error));

    // A label that is itself key-shaped: the label is caller text, so it is
    // classified and not repeated.
    let error = SigningKey::from_pem(&pem(&body, "MAA=")).unwrap_err();
    assert_eq!(error, Error::InvalidKey(KeyRejected::UnsupportedPemLabel));
    assert_no_key_material(&rendered(&error));

    // The two labels this crate reads both reach a PKCS decoder, whose answer now
    // stays in the cause chain. The body must survive nowhere.
    for label in ["RSA PRIVATE KEY", "PRIVATE KEY"] {
        let error = SigningKey::from_pem(&pem(label, &body)).unwrap_err();
        assert!(
            matches!(error, Error::InvalidKeyPem(_)),
            "{label} must report a typed PEM cause, got {error:?}"
        );
        let text = rendered(&error);
        assert_no_key_material(&text);
        assert!(!text.contains(&body[..40]), "the body was echoed: {text}");
    }

    // `ED25519 PRIVATE KEY` is not a label either decoder reads, so it is rejected as
    // unsupported instead of probing a decoder that can only fail. The label and the
    // body both stay out of the message.
    let error = SigningKey::from_pem(&pem("ED25519 PRIVATE KEY", &body)).unwrap_err();
    assert_eq!(error, Error::InvalidKey(KeyRejected::UnsupportedPemLabel));
    assert_no_key_material(&rendered(&error));
}

#[test]
fn dns_record_rejections_never_echo_the_input() {
    let body = marker();

    let cases = [
        (
            format!("v=DKIM1; k=rsa; p={body}"),
            KeyRejected::InvalidRsaPublicKey,
        ),
        (
            format!("v={body}; p=AA=="),
            KeyRejected::UnsupportedRecordVersion,
        ),
        (
            format!("v=DKIM1; k={body}; p=AA=="),
            KeyRejected::UnsupportedKeyType,
        ),
        (
            format!("v=DKIM1; p={body}; p={body}"),
            KeyRejected::DuplicateTag,
        ),
        (format!("v=DKIM1; ={body}"), KeyRejected::EmptyTagName),
        (body.clone(), KeyRejected::TagWithoutEquals),
    ];
    for (record, expected) in cases {
        let error = VerifyingKey::from_dns_record(&record).unwrap_err();
        assert_eq!(error, Error::InvalidKey(expected), "record: {record:?}");
        let text = rendered(&error);
        assert_no_key_material(&text);
        // Even the truncated 40-character echo of a tag without '=' must be gone.
        assert!(
            !text.contains(&body[..40]),
            "a fragment of the record was echoed: {text}"
        );
    }
}

#[test]
fn record_structure_is_classified() {
    let missing = VerifyingKey::from_dns_record("v=DKIM1; k=rsa").unwrap_err();
    assert_eq!(missing, Error::InvalidKey(KeyRejected::MissingPublicKey));

    // The two sides of the revocation rule: an absent p= is a broken record, a
    // present but empty p= is a revoked key, and whitespace is an empty value.
    for revoked in ["v=DKIM1; k=rsa; p=", "v=DKIM1; k=rsa; p=   "] {
        let error = VerifyingKey::from_dns_record(revoked).unwrap_err();
        assert_eq!(
            error,
            Error::InvalidKey(KeyRejected::RevokedKey),
            "{revoked:?}"
        );
    }

    let not_base64 = VerifyingKey::from_dns_record("v=DKIM1; k=ed25519; p=!!!").unwrap_err();
    assert_eq!(
        not_base64,
        Error::InvalidKey(KeyRejected::NotBase64 { what: "p=" })
    );

    // A missing v= is legal: RFC 6376 §3.6.1 defaults the tag.
    let key = SigningKey::from_ed25519_seed(&[5u8; 32]);
    let without_version = key.dns_record().replace("v=DKIM1; ", "");
    assert!(VerifyingKey::from_dns_record(&without_version).is_ok());
}

#[test]
fn ed25519_seed_length_has_an_exact_boundary() {
    for (length, expected) in [(31usize, Some(31)), (32, None), (33, Some(33))] {
        let seed = STANDARD.encode(vec![7u8; length]);
        let outcome = SigningKey::from_ed25519_seed_base64(&seed);
        match expected {
            // 32 is the value inside the limit: it builds a key.
            None => assert_eq!(
                outcome
                    .expect("32 bytes is the length RFC 8032 requires")
                    .algorithm()
                    .as_str(),
                "ed25519-sha256"
            ),
            Some(found) => assert_eq!(
                outcome.unwrap_err(),
                Error::InvalidKey(KeyRejected::WrongLength {
                    what: "Ed25519 seed",
                    expected: 32,
                    found,
                }),
                "{length} bytes must be classified, not accepted"
            ),
        }
    }

    let not_base64 = SigningKey::from_ed25519_seed_base64("!!!").unwrap_err();
    assert_eq!(
        not_base64,
        Error::InvalidKey(KeyRejected::NotBase64 {
            what: "Ed25519 seed"
        })
    );
}

#[test]
fn dns_ed25519_key_length_has_an_exact_boundary() {
    for (length, expected) in [(31usize, Some(31)), (32, None), (33, Some(33))] {
        let record = format!(
            "v=DKIM1; k=ed25519; p={}",
            STANDARD.encode(vec![0x11u8; length])
        );
        let outcome = VerifyingKey::from_dns_record(&record);
        match expected {
            None => assert_eq!(
                outcome
                    .expect("32 bytes is the length RFC 8463 requires")
                    .algorithm()
                    .as_str(),
                "ed25519-sha256"
            ),
            Some(found) => assert_eq!(
                outcome.unwrap_err(),
                Error::InvalidKey(KeyRejected::WrongLength {
                    what: "Ed25519 key",
                    expected: 32,
                    found,
                }),
                "{length} bytes must be classified, not accepted"
            ),
        }
    }

    // Not every 32-byte string is a curve point, and the decoder must say so with
    // the same closed reason. Deterministic: the first rejected byte pattern wins.
    let mut rejected = None;
    for first in 0u8..=255 {
        let mut bytes = [0u8; 32];
        bytes[0] = first;
        if let Err(error) = VerifyingKey::ed25519_from_bytes(&bytes) {
            rejected = Some(error);
            break;
        }
    }
    assert_eq!(
        rejected.expect("a 32-byte string that is not a curve point exists"),
        Error::InvalidKey(KeyRejected::InvalidEd25519PublicKey)
    );
}

#[test]
fn rsa_bit_floor_is_exact() {
    // 1024 bits is the value just inside the RFC 8301 floor: it is accepted.
    let at_floor = SigningKey::from_pem(&fixture("rsa-1024.pem")).expect("1024 bits is allowed");
    assert_eq!(at_floor.algorithm().as_str(), "rsa-sha256");
    assert!(VerifyingKey::from_public_key_pem(&fixture("rsa-1024-public.pem")).is_ok());

    // 512 bits is the value outside it, and the reason carries the counts that were
    // compared instead of a sentence a caller has to parse.
    let below = SigningKey::from_pem(&fixture("rsa-small.pem")).unwrap_err();
    assert_eq!(
        below,
        Error::InvalidKey(KeyRejected::BelowMinimumBits {
            bits: 512,
            minimum: 1024,
        })
    );
    assert!(below.to_string().contains("1024"), "{below}");

    let public = VerifyingKey::from_public_key_pem(&fixture("rsa-small-public.pem")).unwrap_err();
    assert_eq!(
        public,
        Error::InvalidKey(KeyRejected::BelowMinimumBits {
            bits: 512,
            minimum: 1024,
        })
    );

    // The same floor on the DER path, and the DER rejection next to it.
    let der = STANDARD
        .decode(
            fixture("rsa-small-public.pem")
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>()
                .replace(['\n', '\r'], ""),
        )
        .expect("the fixture is base64");
    assert_eq!(
        VerifyingKey::rsa_from_der(&der).unwrap_err(),
        Error::InvalidKey(KeyRejected::BelowMinimumBits {
            bits: 512,
            minimum: 1024,
        })
    );
    assert_eq!(
        VerifyingKey::rsa_from_der(&[0x30, 0x00]).unwrap_err(),
        Error::InvalidKey(KeyRejected::InvalidRsaPublicKey)
    );
}

#[test]
fn a_valid_key_still_loads_after_the_change() {
    // The classification must not cost the happy path: the fixtures the crate ships
    // still sign and verify.
    let key = SigningKey::from_pem(&fixture("rsa-private.pem")).expect("fixture key");
    let record = key.dns_record();
    assert!(record.starts_with("v=DKIM1; k=rsa; p="), "{record}");
    let public = VerifyingKey::from_dns_record(&record).expect("record");
    assert_eq!(public.algorithm(), key.algorithm());
}
