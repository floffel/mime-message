//! The API-review decisions, checked as code instead of kept in a checklist.
//!
//! Three invariants the release gate depends on, re-derived from `src/` on every
//! run:
//!
//! 1. Every public enum or struct is `#[non_exhaustive]`, unless it is listed in
//!    [`EXEMPT`] with the reason it is complete by construction.
//! 2. Every public function carries a doctest, so `missing_docs` plus this test
//!    keep "documented" and "compiles" the same statement.
//! 3. The crate-level `forbid(unsafe_code)` and `deny(missing_docs)` stay in place.
//!
//! A violation is a compile-time *policy* failure here, which is the point: adding
//! a payload enum without `#[non_exhaustive]` should not need a reviewer's memory.

use std::fs;
use std::path::PathBuf;

/// Public types that are deliberately **not** `#[non_exhaustive]`, and why.
///
/// Each entry is also asserted to exist and to still lack the attribute, so a
/// stale entry fails the test instead of silently widening the exemption.
const EXEMPT: [(&str, &str); 6] = [
    (
        "Mailbox",
        "complete RFC 5322 §3.4 mailbox (display name plus address); struct literals are documented API",
    ),
    (
        "Message",
        "carries a private field, so a literal is impossible and a new field is additive",
    ),
    (
        "MessageBuilder",
        "private fields only, built through the setter methods",
    ),
    (
        "Header",
        "private fields only, built through Header::new / Header::from_wire",
    ),
    (
        "SigningKey",
        "opaque private key material, built through the from_pem / from_ed25519_seed constructors",
    ),
    (
        "VerifyingKey",
        "opaque public key material, built through the from_dns_record / from_public_key_pem constructors",
    ),
];

/// One `pub fn`, `pub struct` or `pub enum` declaration and its doc block.
struct Item {
    file: String,
    line: usize,
    kind: &'static str,
    name: String,
    attributes: String,
    fences: usize,
}

impl Item {
    fn is_non_exhaustive(&self) -> bool {
        self.attributes
            .lines()
            .any(|line| line.trim() == "#[non_exhaustive]")
    }
}

/// Every source file of the crate, sorted for a stable failure order.
fn sources() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<PathBuf> = fs::read_dir(&root)
        .expect("src/ is readable")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?")
                .to_string();
            let text = fs::read_to_string(&path).expect("source file is readable");
            (name, text)
        })
        .collect()
}

/// Extracts the public declarations from one source file.
fn items(file: &str, source: &str) -> Vec<Item> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (kind, name) = match words.as_slice() {
            ["pub", "fn", rest, ..] => ("fn", rest.trim_start_matches('(').to_string()),
            ["pub", "async", "fn", rest, ..] => ("fn", rest.to_string()),
            ["pub", "struct", rest, ..] => ("struct", rest.to_string()),
            ["pub", "enum", rest, ..] => ("enum", rest.to_string()),
            _ => continue,
        };
        // `fn render(&self)` -> `render`; `struct Foo<T>` -> `Foo`.
        let name = name
            .split(['(', '<', '{', ':'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }

        // Attributes sit directly above the declaration, doc comments above them.
        let mut cursor = index;
        let mut attributes = String::new();
        while cursor > 0 {
            let previous = lines[cursor - 1].trim();
            if previous.starts_with("#[") {
                attributes.push_str(previous);
                attributes.push('\n');
                cursor -= 1;
            } else {
                break;
            }
        }
        let mut fences = 0;
        while cursor > 0 {
            let previous = lines[cursor - 1].trim();
            if previous.starts_with("///") {
                if previous
                    .trim_start_matches('/')
                    .trim_start()
                    .starts_with("```")
                {
                    fences += 1;
                }
                cursor -= 1;
            } else {
                break;
            }
        }

        out.push(Item {
            file: file.to_string(),
            line: index + 1,
            kind,
            name,
            attributes,
            fences,
        });
    }
    out
}

fn all_items() -> Vec<Item> {
    sources()
        .iter()
        .flat_map(|(file, text)| items(file, text))
        .collect()
}

#[test]
fn public_types_are_non_exhaustive_or_exempt_with_a_reason() {
    let mut violations: Vec<String> = Vec::new();
    for item in all_items().iter().filter(|item| item.kind != "fn") {
        if item.is_non_exhaustive() {
            continue;
        }
        if EXEMPT.iter().any(|(name, _)| *name == item.name) {
            continue;
        }
        violations.push(format!(
            "{}:{}: pub {} {} is neither #[non_exhaustive] nor listed in EXEMPT",
            item.file, item.line, item.kind, item.name
        ));
    }
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "public types must state how they may grow:\n{}",
        violations.join("\n")
    );
}

#[test]
fn exemptions_are_real_and_still_exhaustive() {
    let items = all_items();
    let mut problems: Vec<String> = Vec::new();
    for (name, reason) in EXEMPT {
        let found: Vec<&Item> = items
            .iter()
            .filter(|item| item.name == name && item.kind != "fn")
            .collect();
        if found.is_empty() {
            problems.push(format!(
                "EXEMPT names `{name}` ({reason}), but no such type exists"
            ));
        } else if found.iter().any(|item| item.is_non_exhaustive()) {
            problems.push(format!(
                "EXEMPT names `{name}`, but it is #[non_exhaustive] - drop the entry"
            ));
        }
    }
    assert_eq!(
        problems,
        Vec::<String>::new(),
        "the exemption list must match the source:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_public_function_is_documented_with_a_doctest() {
    let mut violations: Vec<String> = Vec::new();
    for item in all_items().iter().filter(|item| item.kind == "fn") {
        if item.fences < 2 {
            violations.push(format!(
                "{}:{}: pub fn {} has {} fence line(s) in its doc block, a doctest needs 2",
                item.file, item.line, item.name, item.fences
            ));
        }
    }
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "every public function needs a runnable example:\n{}",
        violations.join("\n")
    );
}

#[test]
fn crate_level_lints_stay_in_place() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let lib = fs::read_to_string(root).expect("src/lib.rs is readable");
    for required in ["#![forbid(unsafe_code)]", "#![deny(missing_docs)]"] {
        assert!(
            lib.contains(required),
            "src/lib.rs lost `{required}`, which the quality bar requires"
        );
    }
}

/// The README is documentation that runs, not prose next to the code.
///
/// `lib.rs` pulls `README.md` into the crate documentation under `cfg(doctest)`,
/// so `cargo test --doc` compiles and executes the quick start and the `cid:`
/// example. Deleting that one attribute silently turns both back into text that
/// cannot fail, which is exactly the drift this test refuses.
#[test]
fn readme_rust_blocks_are_compiled_as_doctests() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib = fs::read_to_string(root.join("src/lib.rs")).expect("src/lib.rs is readable");
    let hook = r#"#![cfg_attr(doctest, doc = include_str!("../README.md"))]"#;
    assert!(
        lib.contains(hook),
        "src/lib.rs lost `{hook}`, so the README is no longer compiled by `cargo test --doc`"
    );

    let readme = fs::read_to_string(root.join("README.md")).expect("README.md is readable");
    let runnable = readme
        .lines()
        .filter(|line| line.starts_with("```rust") && !line.contains("ignore"))
        .count();
    assert!(
        runnable >= 2,
        "README.md has {runnable} compiled Rust block(s): the quick start and the `cid:` example are both programs"
    );
    assert!(
        readme.contains("fn main() -> Result<(), Box<dyn std::error::Error>>"),
        "the README examples stay full programs, so they also compile when copied out of the page"
    );
}
