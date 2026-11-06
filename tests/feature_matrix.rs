//! Release-gate checks for the feature matrix and the no-I/O promise.
//!
//! CI runs the suite with default features and with no default features. These
//! tests make the configuration itself explicit: `dkim` is the only feature,
//! it is optional, and neither configuration can pull in a network or HTTP
//! dependency.

use std::fs;
use std::path::PathBuf;

fn manifest() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    fs::read_to_string(path).expect("Cargo.toml is readable")
}

fn source(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{name} is readable: {error}"))
}

fn lockfile() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    fs::read_to_string(path).expect("Cargo.lock is readable")
}

#[test]
fn default_feature_set_is_empty_and_dkim_is_optional() {
    let manifest = manifest();
    let features = manifest
        .split_once("[features]")
        .and_then(|(_, rest)| rest.split_once("\n["))
        .map(|(features, _)| features)
        .expect("Cargo.toml has a features table followed by another table");

    assert!(
        features.lines().any(|line| line.trim() == "default = []"),
        "the default feature set must stay empty:\n{features}"
    );
    assert!(
        features.lines().any(|line| {
            let line = line.trim();
            line.starts_with("dkim = [") && line.contains("dep:rsa") && line.contains("dep:pem")
        }),
        "dkim must remain an opt-in feature that activates its dependencies:\n{features}"
    );
}

#[test]
fn dependency_graph_has_no_network_or_http_client() {
    let manifest = manifest();
    let lockfile = lockfile();
    let forbidden = [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "attohttpc",
        "surf",
        "tokio",
        "async-std",
        "smol",
        "mio",
        "socket2",
    ];

    for (index, line) in manifest.lines().enumerate() {
        let Some((name, _)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        assert!(
            !forbidden.contains(&name),
            "Cargo.toml:{} adds network/runtime dependency `{name}`; this crate is I/O-free",
            index + 1
        );
    }

    for package in forbidden {
        assert!(
            !lockfile.contains(&format!("name = \"{package}\"")),
            "Cargo.lock resolves network/runtime package `{package}`; this crate is I/O-free"
        );
    }

    for name in [
        "lib.rs",
        "charset.rs",
        "cid.rs",
        "error.rs",
        "header.rs",
        "parse.rs",
        "render.rs",
        "rfc2047.rs",
        "stream.rs",
        "transfer.rs",
    ] {
        let text = source(name);
        for forbidden in ["std::net", "TcpStream", "UdpSocket", "reqwest::", "hyper::"] {
            assert!(
                !text.contains(forbidden),
                "src/{name} contains network API `{forbidden}`"
            );
        }
    }
}

#[test]
fn dkim_module_is_gated_by_the_feature() {
    let lib = source("lib.rs");
    assert!(
        lib.contains("#[cfg(feature = \"dkim\")]\npub mod dkim;"),
        "the dkim module must be compiled only with the dkim feature"
    );
}

#[cfg(feature = "dkim")]
#[test]
fn all_features_expose_dkim_and_the_dkim_error_path() {
    use mime_message::dkim::SigningKey;
    use mime_message::{Error, KeyRejected};

    let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
    assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
    assert_eq!(
        SigningKey::from_ed25519_seed_base64("not base64!").unwrap_err(),
        Error::InvalidKey(KeyRejected::NotBase64 {
            what: "Ed25519 seed"
        })
    );
}

#[cfg(not(feature = "dkim"))]
#[test]
fn no_default_features_keep_the_core_error_paths() {
    use mime_message::{parse, Error};

    assert_eq!(parse("").unwrap_err(), Error::EmptyMessage);
    assert_eq!(
        parse("From: a@example.com\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody")
            .unwrap_err(),
        Error::DuplicateHeader("Content-Type".to_string())
    );
}
