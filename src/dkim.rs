//! DKIM (RFC 6376) signing and verification, behind the `dkim` feature.
//!
//! String building here is straight-line formatting; `String` writes cannot
//! fail, so threading `write!` through every helper would only add noise.
#![allow(clippy::format_push_string)]
//!
//! `DomainKeys Identified Mail` signs a message so a receiver can tell whether it
//! was modified in transit. The crate implements the two algorithms that are
//! actually deployed:
//!
//! - `rsa-sha256` (RFC 6376) with RSA keys of at least 1024 bits (RFC 8301),
//! - `ed25519-sha256` (RFC 8463).
//!
//! Both canonicalizations (`simple` and `relaxed`) are supported for headers
//! and body, and `l=` is honoured while verifying. Nothing here touches the
//! network: the caller supplies the private key for signing and the public key
//! from the selector's DNS record for verifying.
//!
//! ```
//! use mime_message::{dkim, Message};
//!
//! # fn main() -> Result<(), mime_message::Error> {
//! let key = dkim::SigningKey::from_ed25519_seed(&[7u8; 32]);
//! let params = dkim::SignParams::new("example.com", "sel");
//! let message = Message::builder()
//!     .from("a@example.com")?
//!     .to("b@example.com")?
//!     .subject("hi")
//!     .body("there")
//!     .build()?;
//!
//! let signed = message.sign(&key, &params)?;
//! let raw = String::from_utf8_lossy(&signed);
//! assert!(raw.starts_with("DKIM-Signature: v=1; a=ed25519-sha256;"));
//!
//! let verified = dkim::verify(&raw, &key.verifying_key())?;
//! assert_eq!(verified.domain, "example.com");
//! assert_eq!(verified.selector, "sel");
//! # Ok(())
//! # }
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Verifier as _;
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePublicKey as _};
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::error::{Error, Result};
use crate::{truncate, Message};

/// Smallest RSA modulus accepted, in bits (RFC 8301 §3.2).
const MIN_RSA_BITS: usize = 1024;

/// Longest line a folded `DKIM-Signature` may occupy.
const MAX_LINE: usize = 78;

/// The signature algorithm named in the `a=` tag.
///
/// ```
/// use mime_message::dkim::Algorithm;
///
/// assert_eq!(Algorithm::RsaSha256.as_str(), "rsa-sha256");
/// assert_eq!(Algorithm::Ed25519Sha256.as_str(), "ed25519-sha256");
/// assert_eq!(Algorithm::parse("ed25519-sha256"), Some(Algorithm::Ed25519Sha256));
/// assert_eq!(Algorithm::parse("rsa-sha1"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSA PKCS#1 v1.5 over SHA-256.
    RsaSha256,
    /// Ed25519 over SHA-256 (RFC 8463).
    Ed25519Sha256,
}

impl Algorithm {
    /// The `a=` tag value.
    ///
    /// ```
    /// use mime_message::dkim::Algorithm;
    ///
    /// assert_eq!(Algorithm::RsaSha256.as_str(), "rsa-sha256");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }

    /// Parses an `a=` tag value, returning `None` for algorithms we do not do.
    ///
    /// ```
    /// use mime_message::dkim::Algorithm;
    ///
    /// assert_eq!(Algorithm::parse("RSA-SHA256"), Some(Algorithm::RsaSha256));
    /// assert_eq!(Algorithm::parse("rsa-sha1"), None);
    /// ```
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "rsa-sha256" => Some(Self::RsaSha256),
            "ed25519-sha256" => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }
}

/// Header and body canonicalization (RFC 6376 §3.4).
///
/// ```
/// use mime_message::dkim::Canonicalization;
///
/// assert_eq!(Canonicalization::Relaxed.as_str(), "relaxed");
/// assert_eq!(Canonicalization::parse("SIMPLE"), Some(Canonicalization::Simple));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalization {
    /// Byte-for-byte, only normalising line endings.
    Simple,
    /// Case, whitespace and folding insensitive.
    Relaxed,
}

impl Canonicalization {
    /// The `c=` tag spelling.
    ///
    /// ```
    /// use mime_message::dkim::Canonicalization;
    ///
    /// assert_eq!(Canonicalization::Simple.as_str(), "simple");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Relaxed => "relaxed",
        }
    }

    /// Parses one half of a `c=` tag.
    ///
    /// ```
    /// use mime_message::dkim::Canonicalization;
    ///
    /// assert_eq!(
    ///     Canonicalization::parse("Relaxed"),
    ///     Some(Canonicalization::Relaxed)
    /// );
    /// assert_eq!(Canonicalization::parse("strict"), None);
    /// ```
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "simple" => Some(Self::Simple),
            "relaxed" => Some(Self::Relaxed),
            _ => None,
        }
    }
}

/// A private key used to sign.
///
/// ```
/// use mime_message::dkim::SigningKey;
///
/// let key = SigningKey::from_ed25519_seed(&[1u8; 32]);
/// assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
/// // The DNS TXT record a verifier needs.
/// assert!(key.dns_record().starts_with("v=DKIM1; k=ed25519; p="));
/// ```
#[derive(Clone)]
pub struct SigningKey {
    material: KeyMaterial,
}

#[derive(Clone)]
enum KeyMaterial {
    Rsa(Box<RsaPrivateKey>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl std::fmt::Debug for SigningKey {
    /// Shows the algorithm only — a private key must never reach a log line.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Builds an Ed25519 key from its 32-byte seed.
    ///
    /// This is the form RFC 8463 §A.1 publishes and the form most automation
    /// has at hand.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let key = SigningKey::from_ed25519_seed(&[3u8; 32]);
    /// assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
    /// ```
    #[must_use]
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self {
            material: KeyMaterial::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(seed))),
        }
    }

    /// Builds an Ed25519 key from a base64-encoded 32-byte seed.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let key = SigningKey::from_ed25519_seed_base64(
    ///     "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=",
    /// )?;
    /// assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] when the value is not base64 or does not decode to
    /// exactly 32 bytes.
    pub fn from_ed25519_seed_base64(seed: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(seed.trim())
            .map_err(|_| Error::InvalidKey("Ed25519 seed is not base64".to_string()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("Ed25519 seed must be 32 bytes".to_string()))?;
        Ok(Self::from_ed25519_seed(&seed))
    }

    /// Reads a PEM-encoded private key: RSA (PKCS#1 or PKCS#8) or Ed25519
    /// (PKCS#8).
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let pem = std::fs::read_to_string("tests/fixtures/rsa-private.pem")?;
    /// let key = SigningKey::from_pem(&pem)?;
    /// assert_eq!(key.algorithm().as_str(), "rsa-sha256");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] for anything that is not an unencrypted RSA or
    /// Ed25519 private key, and for RSA keys below 1024 bits.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let label = pem_label(pem)
            .ok_or_else(|| Error::InvalidKey("not a PEM block (no BEGIN line)".to_string()))?;
        match label.as_str() {
            "RSA PRIVATE KEY" => {
                let key = RsaPrivateKey::from_pkcs1_pem(pem)
                    .map_err(|error| Error::InvalidKey(format!("RSA PKCS#1: {error}")))?;
                Self::from_rsa(key)
            }
            "PRIVATE KEY" | "ED25519 PRIVATE KEY" => {
                if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
                    return Ok(Self {
                        material: KeyMaterial::Ed25519(Box::new(key)),
                    });
                }
                let key = RsaPrivateKey::from_pkcs8_pem(pem)
                    .map_err(|error| Error::InvalidKey(format!("PKCS#8: {error}")))?;
                Self::from_rsa(key)
            }
            other => Err(Error::InvalidKey(format!(
                "unsupported PEM label {other:?}"
            ))),
        }
    }

    fn from_rsa(key: RsaPrivateKey) -> Result<Self> {
        let bits = key.size() * 8;
        if bits < MIN_RSA_BITS {
            return Err(Error::InvalidKey(format!(
                "RSA key is {bits} bits, RFC 8301 requires at least {MIN_RSA_BITS}"
            )));
        }
        Ok(Self {
            material: KeyMaterial::Rsa(Box::new(key)),
        })
    }

    /// The algorithm this key signs with.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let key = SigningKey::from_pem(
    ///     &std::fs::read_to_string("tests/fixtures/rsa-private.pem")?,
    /// )?;
    /// assert_eq!(key.algorithm().as_str(), "rsa-sha256");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self.material {
            KeyMaterial::Rsa(_) => Algorithm::RsaSha256,
            KeyMaterial::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }

    /// The matching public key.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let key = SigningKey::from_ed25519_seed(&[9u8; 32]);
    /// assert_eq!(key.verifying_key().algorithm(), key.algorithm());
    /// ```
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        match &self.material {
            KeyMaterial::Rsa(private) => VerifyingKey {
                material: PublicMaterial::Rsa(Box::new(private.to_public_key())),
            },
            KeyMaterial::Ed25519(private) => VerifyingKey {
                material: PublicMaterial::Ed25519(Box::new(private.verifying_key())),
            },
        }
    }

    /// The DNS TXT record for `selector._domainkey.domain`.
    ///
    /// Publish this string at the selector so receivers can verify. It is the
    /// same shape [`VerifyingKey::from_dns_record`] reads.
    ///
    /// ```
    /// use mime_message::dkim::SigningKey;
    ///
    /// let key = SigningKey::from_ed25519_seed(&[4u8; 32]);
    /// let record = key.dns_record();
    /// assert!(record.contains("v=DKIM1; k=ed25519; p="));
    /// ```
    #[must_use]
    pub fn dns_record(&self) -> String {
        match &self.material {
            KeyMaterial::Rsa(private) => private.to_public_key().to_public_key_der().map_or_else(
                // A record we cannot encode is published without a key, so
                // every verifier rejects it instead of trusting it.
                |_| "v=DKIM1; k=rsa; p=".to_string(),
                |der| format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(der.as_bytes())),
            ),
            KeyMaterial::Ed25519(private) => format!(
                "v=DKIM1; k=ed25519; p={}",
                STANDARD.encode(private.verifying_key().to_bytes())
            ),
        }
    }

    fn sign(&self, input: &[u8]) -> Vec<u8> {
        match &self.material {
            KeyMaterial::Rsa(private) => {
                // `SigningKey` owns the key; cloning it is far cheaper than a signature.
                let signing = RsaSigningKey::<Sha256>::new((**private).clone());
                signing.sign(input).to_vec()
            }
            // RFC 8463 §3: ed25519-sha256 hashes the canonicalized headers
            // with SHA-256 first and signs that digest.
            KeyMaterial::Ed25519(private) => {
                private.sign(&Sha256::digest(input)).to_bytes().to_vec()
            }
        }
    }
}

/// A public key used to verify.
///
/// ```
/// use mime_message::dkim::VerifyingKey;
///
/// let record = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
/// let key = VerifyingKey::from_dns_record(record)?;
/// assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
/// # Ok::<(), mime_message::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    material: PublicMaterial,
}

#[derive(Debug, Clone)]
enum PublicMaterial {
    Rsa(Box<RsaPublicKey>),
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

impl VerifyingKey {
    /// Reads a DKIM DNS TXT record (`v=DKIM1; k=rsa; p=…`).
    ///
    /// Unknown tags are ignored, `k=` defaults to `rsa`, and an empty `p=`
    /// (a revoked key) is an error rather than a silent pass.
    ///
    /// ```
    /// use mime_message::dkim::VerifyingKey;
    ///
    /// // A revoked key must not verify anything.
    /// assert!(VerifyingKey::from_dns_record("v=DKIM1; k=rsa; p=").is_err());
    /// assert!(VerifyingKey::from_dns_record("v=DKIM2; k=rsa; p=AAAA").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] for a wrong version, an unsupported key type, a
    /// missing or revoked `p=`, base64 that does not decode, SPKI that is not
    /// an RSA key, or an RSA key below 1024 bits.
    pub fn from_dns_record(record: &str) -> Result<Self> {
        let tags = parse_tags(record)
            .map_err(|error| Error::InvalidKey(format!("DNS record: {error}")))?;
        if let Some(version) = tags.get("v") {
            if version.trim() != "DKIM1" {
                return Err(Error::InvalidKey(format!(
                    "unsupported key record version {version:?}"
                )));
            }
        }
        let kind = tags.get("k").map_or("rsa", String::as_str);
        let encoded = tags
            .get("p")
            .ok_or_else(|| Error::InvalidKey("DNS record has no p= tag".to_string()))?;
        let compressed: String = encoded.chars().filter(|ch| !ch.is_whitespace()).collect();
        if compressed.is_empty() {
            return Err(Error::InvalidKey(
                "DNS record has a revoked key (p=)".to_string(),
            ));
        }
        let der = STANDARD
            .decode(&compressed)
            .map_err(|_| Error::InvalidKey("p= is not base64".to_string()))?;
        match kind.trim().to_ascii_lowercase().as_str() {
            "rsa" => Self::rsa_from_der(&der),
            "ed25519" => {
                let bytes: [u8; 32] = der
                    .try_into()
                    .map_err(|_| Error::InvalidKey("Ed25519 key must be 32 bytes".to_string()))?;
                Self::ed25519_from_bytes(&bytes)
            }
            other => Err(Error::InvalidKey(format!("unsupported key type {other:?}"))),
        }
    }

    /// Wraps an RSA public key in `SubjectPublicKeyInfo` DER form (the `p=`
    /// payload of an RSA DKIM record).
    ///
    /// ```
    /// use mime_message::dkim::VerifyingKey;
    ///
    /// let der = [0x30, 0x00]; // not a real key
    /// assert!(VerifyingKey::rsa_from_der(&der).is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] when the DER is not an RSA public key of at least
    /// 1024 bits.
    pub fn rsa_from_der(der: &[u8]) -> Result<Self> {
        let key = RsaPublicKey::from_public_key_der(der)
            .map_err(|error| Error::InvalidKey(format!("RSA public key: {error}")))?;
        let bits = key.size() * 8;
        if bits < MIN_RSA_BITS {
            return Err(Error::InvalidKey(format!(
                "RSA key is {bits} bits, RFC 8301 requires at least {MIN_RSA_BITS}"
            )));
        }
        Ok(Self {
            material: PublicMaterial::Rsa(Box::new(key)),
        })
    }

    /// Wraps an Ed25519 public key in its raw 32-byte form.
    ///
    /// ```
    /// use mime_message::dkim::VerifyingKey;
    ///
    /// let bytes = [0x11; 32];
    /// assert_eq!(
    ///     VerifyingKey::ed25519_from_bytes(&bytes)?.algorithm().as_str(),
    ///     "ed25519-sha256"
    /// );
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] when the bytes are not a valid curve point.
    pub fn ed25519_from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|error| Error::InvalidKey(format!("Ed25519 public key: {error}")))?;
        Ok(Self {
            material: PublicMaterial::Ed25519(Box::new(key)),
        })
    }

    /// Reads a PEM `PUBLIC KEY` block (RSA in SPKI form).
    ///
    /// ```
    /// use mime_message::dkim::VerifyingKey;
    ///
    /// assert!(VerifyingKey::from_public_key_pem("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] when the PEM is not a readable RSA public key.
    pub fn from_public_key_pem(pem: &str) -> Result<Self> {
        let key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|error| Error::InvalidKey(format!("RSA public key: {error}")))?;
        let bits = key.size() * 8;
        if bits < MIN_RSA_BITS {
            return Err(Error::InvalidKey(format!(
                "RSA key is {bits} bits, RFC 8301 requires at least {MIN_RSA_BITS}"
            )));
        }
        Ok(Self {
            material: PublicMaterial::Rsa(Box::new(key)),
        })
    }

    /// The algorithm this key verifies.
    ///
    /// ```
    /// use mime_message::dkim::VerifyingKey;
    ///
    /// let key = VerifyingKey::from_dns_record(
    ///     "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
    /// )?;
    /// assert_eq!(key.algorithm().as_str(), "ed25519-sha256");
    /// # Ok::<(), mime_message::Error>(())
    /// ```
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self.material {
            PublicMaterial::Rsa(_) => Algorithm::RsaSha256,
            PublicMaterial::Ed25519(_) => Algorithm::Ed25519Sha256,
        }
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        match &self.material {
            PublicMaterial::Rsa(public) => {
                let verifying = RsaVerifyingKey::<Sha256>::new((**public).clone());
                let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| {
                    Error::InvalidSignature("RSA signature is malformed".to_string())
                })?;
                verifying
                    .verify(input, &signature)
                    .map_err(|_| Error::SignatureMismatch)
            }
            PublicMaterial::Ed25519(public) => {
                let bytes: [u8; 64] = signature.try_into().map_err(|_| {
                    Error::InvalidSignature("Ed25519 signature must be 64 bytes".to_string())
                })?;
                let signature = ed25519_dalek::Signature::from_bytes(&bytes);
                public
                    .verify_strict(&Sha256::digest(input), &signature)
                    .map_err(|_| Error::SignatureMismatch)
            }
        }
    }
}

/// What to put into a `DKIM-Signature` when signing.
///
/// ```
/// use mime_message::dkim::{Canonicalization, SignParams};
///
/// let params = SignParams::new("example.com", "mail")
///     .canonicalization(Canonicalization::Relaxed, Canonicalization::Relaxed)
///     .identity("@example.com")
///     .timestamp(1_700_000_000);
/// assert_eq!(params.domain, "example.com");
/// assert_eq!(params.selector, "mail");
/// ```
///
/// The timestamp is caller supplied on purpose: this crate never reads the
/// clock, so signing the same message twice produces the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignParams {
    /// The signing domain (`d=`), for example `example.com`.
    pub domain: String,
    /// The selector (`s=`), the DNS label under `_domainkey`.
    pub selector: String,
    /// Optional identity (`i=`), normally `@domain`.
    pub identity: Option<String>,
    /// Header canonicalization, `relaxed` by default.
    pub header_canonicalization: Canonicalization,
    /// Body canonicalization, `relaxed` by default.
    pub body_canonicalization: Canonicalization,
    /// Optional signature timestamp (`t=`), Unix seconds.
    pub timestamp: Option<u64>,
    /// Header names to sign, in `h=` order.
    ///
    /// `None` signs every header field present except `DKIM-Signature`. An
    /// explicit list is for callers who want a stable signature across
    /// re-rendering.
    pub signed_headers: Option<Vec<String>>,
}

impl SignParams {
    /// Parameters with relaxed/relaxed canonicalization and no timestamp.
    ///
    /// ```
    /// use mime_message::dkim::SignParams;
    ///
    /// let params = SignParams::new("example.com", "sel");
    /// assert_eq!(params.selector, "sel");
    /// assert!(params.timestamp.is_none());
    /// ```
    #[must_use]
    pub fn new(domain: impl Into<String>, selector: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            selector: selector.into(),
            identity: None,
            header_canonicalization: Canonicalization::Relaxed,
            body_canonicalization: Canonicalization::Relaxed,
            timestamp: None,
            signed_headers: None,
        }
    }

    /// Sets both canonicalizations.
    ///
    /// ```
    /// # use mime_message::dkim::{Canonicalization, SignParams};
    /// let params = SignParams::new("example.com", "sel")
    ///     .canonicalization(Canonicalization::Simple, Canonicalization::Relaxed);
    /// assert_eq!(params.header_canonicalization, Canonicalization::Simple);
    /// ```
    #[must_use]
    pub fn canonicalization(mut self, header: Canonicalization, body: Canonicalization) -> Self {
        self.header_canonicalization = header;
        self.body_canonicalization = body;
        self
    }

    /// Sets the `i=` identity.
    ///
    /// ```
    /// # use mime_message::dkim::SignParams;
    /// let params = SignParams::new("example.com", "sel").identity("@example.com");
    /// assert_eq!(params.identity.as_deref(), Some("@example.com"));
    /// ```
    #[must_use]
    pub fn identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Sets the `t=` timestamp (Unix seconds), keeping rendering deterministic.
    ///
    /// ```
    /// # use mime_message::dkim::SignParams;
    /// let params = SignParams::new("example.com", "sel").timestamp(0);
    /// assert_eq!(params.timestamp, Some(0));
    /// ```
    #[must_use]
    pub fn timestamp(mut self, seconds: u64) -> Self {
        self.timestamp = Some(seconds);
        self
    }

    /// Restricts the signed header fields, in `h=` order.
    ///
    /// `From` is added when missing: RFC 6376 §5.4 requires it.
    ///
    /// ```
    /// # use mime_message::dkim::SignParams;
    /// let params = SignParams::new("example.com", "sel")
    ///     .signed_headers(["Subject"]);
    /// assert_eq!(params.signed_headers.as_deref(), Some(&["Subject".to_string()][..]));
    /// ```
    #[must_use]
    pub fn signed_headers<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.signed_headers = Some(names.into_iter().map(Into::into).collect());
        self
    }
}

/// A parsed `DKIM-Signature` header field.
///
/// ```
/// use mime_message::dkim;
///
/// let raw = concat!(
///     "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com;\r\n",
///     " s=sel; h=from:subject; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;\r\n",
///     " b=AAAA\r\n",
///     "From: a@example.com\r\n",
///     "Subject: hi\r\n",
///     "\r\n",
///     "body",
/// );
/// let signature = &dkim::signatures(raw)?[0];
/// assert_eq!(signature.domain, "example.com");
/// assert_eq!(signature.signed_headers, ["from", "subject"]);
/// # Ok::<(), mime_message::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader {
    /// `d=` — the signing domain.
    pub domain: String,
    /// `s=` — the selector.
    pub selector: String,
    /// `a=` — the algorithm.
    pub algorithm: Algorithm,
    /// First half of `c=` (header canonicalization).
    pub header_canonicalization: Canonicalization,
    /// Second half of `c=` (body canonicalization).
    pub body_canonicalization: Canonicalization,
    /// `h=` — the signed header names, in signing order.
    pub signed_headers: Vec<String>,
    /// `bh=` — the declared body hash.
    pub body_hash: Vec<u8>,
    /// `b=` — the signature itself.
    pub signature: Vec<u8>,
    /// `i=` — the claimed identity, when present.
    pub identity: Option<String>,
    /// `t=` — the signing timestamp, when present.
    pub timestamp: Option<u64>,
    /// `l=` — how many canonicalized body bytes were signed, when present.
    pub body_length: Option<usize>,
}

/// Returns every `DKIM-Signature` header field in `raw`, in message order.
///
/// ```
/// use mime_message::dkim;
///
/// assert_eq!(dkim::signatures("From: a@example.com\r\n\r\nhi").unwrap().len(), 0);
/// ```
///
/// # Errors
///
/// [`Error::InvalidSignature`] when a `DKIM-Signature` field is malformed —
/// missing required tags, duplicated tags, unknown algorithm or
/// canonicalization, or base64 that does not decode.
pub fn signatures(raw: &str) -> Result<Vec<SignatureHeader>> {
    let (head, _) = split_head(raw);
    let mut out = Vec::new();
    for field in header_fields(head) {
        if field.name.eq_ignore_ascii_case("DKIM-Signature") {
            out.push(SignatureHeader::parse(&field)?);
        }
    }
    Ok(out)
}

impl SignatureHeader {
    fn parse(field: &Field) -> Result<Self> {
        let value = field.value();
        let tags = parse_tags(value).map_err(Error::InvalidSignature)?;
        let require = |name: &str| -> Result<&str> {
            tags.get(name)
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| Error::InvalidSignature(format!("missing {name}= tag")))
        };
        if require("v")?.trim() != "1" {
            return Err(Error::InvalidSignature("unsupported v= tag".to_string()));
        }
        let algorithm = Algorithm::parse(require("a")?).ok_or_else(|| {
            Error::InvalidSignature(format!("unsupported algorithm {:?}", require("a")))
        })?;
        let canonicalization = tags.get("c").map_or("simple/simple", String::as_str);
        let parse_one = |label: &str| -> Result<Canonicalization> {
            Canonicalization::parse(label).ok_or_else(|| {
                Error::InvalidSignature(format!("unknown canonicalization {label:?}"))
            })
        };
        let (header_canonicalization, body_canonicalization) =
            if let Some((header, body)) = canonicalization.split_once('/') {
                (parse_one(header)?, parse_one(body)?)
            } else {
                let both = parse_one(canonicalization)?;
                (both, both)
            };
        let signed_headers = require("h")?
            .split(':')
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        if signed_headers.is_empty() {
            return Err(Error::InvalidSignature(
                "h= names no header fields".to_string(),
            ));
        }
        if !signed_headers.iter().any(|name| name == "from") {
            return Err(Error::InvalidSignature(
                "h= does not cover the From header".to_string(),
            ));
        }
        let body_hash = decode_b64(require("bh")?, "bh=")?;
        let signature = decode_b64(require("b")?, "b=")?;
        let timestamp =
            match tags.get("t") {
                Some(raw) => Some(raw.trim().parse::<u64>().map_err(|_| {
                    Error::InvalidSignature(format!("t= is not a timestamp: {raw:?}"))
                })?),
                None => None,
            };
        let body_length = match tags.get("l") {
            Some(raw) => {
                let length = raw
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::InvalidSignature(format!("l= is not a length: {raw:?}")))?;
                Some(length)
            }
            None => None,
        };
        Ok(Self {
            domain: require("d")?.trim().to_string(),
            selector: require("s")?.trim().to_string(),
            algorithm,
            header_canonicalization,
            body_canonicalization,
            signed_headers,
            body_hash,
            signature,
            identity: tags.get("i").map(|value| value.trim().to_string()),
            timestamp,
            body_length,
        })
    }
}

/// Signs `message` and returns the bytes to send (signature header included).
///
/// ```
/// use mime_message::dkim::{SignParams, SigningKey};
/// use mime_message::Message;
///
/// let key = SigningKey::from_ed25519_seed(&[2u8; 32]);
/// let signed = Message::builder()
///     .from("a@example.com")?
///     .to("b@example.com")?
///     .body("hi")
///     .build()?
///     .sign(&key, &SignParams::new("example.com", "sel"))?;
/// assert!(String::from_utf8_lossy(&signed).starts_with("DKIM-Signature: "));
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::HeaderInjection`] and friends from rendering, and
/// [`Error::InvalidSignature`] when the message has no `From` to sign.
pub fn sign(message: &Message, key: &SigningKey, params: &SignParams) -> Result<Vec<u8>> {
    let rendered = message.render()?;
    let rendered = String::from_utf8(rendered)
        .map_err(|_| Error::InvalidSignature("rendered message is not UTF-8".to_string()))?;
    let (head, body) = split_head(&rendered);
    let fields = header_fields(head);

    // Which fields to sign, in the order the `h=` tag will list them. Duplicate
    // names are listed once per occurrence, so a receiver consuming instances
    // bottom-up covers every one of them.
    let mut signed: Vec<String> = Vec::new();
    for field in &fields {
        if field.name.eq_ignore_ascii_case("DKIM-Signature") {
            continue;
        }
        signed.push(field.name.clone());
    }
    if let Some(explicit) = &params.signed_headers {
        signed = explicit
            .iter()
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        if !signed.iter().any(|name| name == "from") {
            signed.insert(0, "from".to_string());
        }
    }
    let canonical_body = canonicalize_body(body.as_bytes(), params.body_canonicalization, None);
    let body_hash = Sha256::digest(&canonical_body);

    let mut value = format!(
        "v=1; a={}; c={}/{}; d={}; s={};",
        key.algorithm().as_str(),
        params.header_canonicalization.as_str(),
        params.body_canonicalization.as_str(),
        params.domain,
        params.selector,
    );
    if let Some(identity) = &params.identity {
        value.push_str(&format!(" i={identity};"));
    }
    if let Some(timestamp) = params.timestamp {
        value.push_str(&format!(" t={timestamp};"));
    }
    value.push_str(&format!(" h={};", signed.join(":")));
    value.push_str(&format!(" bh={};", STANDARD.encode(body_hash)));
    value.push_str(" b=");

    let prefix = fold_field("DKIM-Signature", &value);
    let signed_header = Field {
        name: "DKIM-Signature".to_string(),
        raw: prefix.clone(),
    };
    // `signing_input` leaves the trailing CRLF off the last header, as
    // RFC 6376 §3.7 requires.
    let input = signing_input(
        &fields,
        &signed,
        params.header_canonicalization,
        &signed_header,
    );

    let signature = key.sign(&input);
    let mut header = prefix;
    header.push_str(&fold_base64(&STANDARD.encode(signature)));
    header.push_str("\r\n");
    header.push_str(&rendered);
    Ok(header.into_bytes())
}

/// Verifies every `DKIM-Signature` in `raw` until one verifies with `key`.
///
/// ```
/// use mime_message::dkim::{self, SignParams, SigningKey};
/// use mime_message::Message;
///
/// let key = SigningKey::from_ed25519_seed(&[5u8; 32]);
/// let signed = Message::builder()
///     .from("a@example.com")?
///     .to("b@example.com")?
///     .body("hi")
///     .build()?
///     .sign(&key, &SignParams::new("example.com", "sel"))?;
/// let raw = String::from_utf8_lossy(&signed);
/// let verified = dkim::verify(&raw, &key.verifying_key())?;
/// assert_eq!(verified.domain, "example.com");
///
/// // Any change to the body breaks the signature.
/// let tampered = raw.replace("hi", "ho");
/// assert!(dkim::verify(&tampered, &key.verifying_key()).is_err());
/// # Ok::<(), mime_message::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::MissingSignature`] when the message has no signature at all,
/// [`Error::NoMatchingSignature`] when none uses the key's algorithm,
/// [`Error::BodyHashMismatch`] and [`Error::SignatureMismatch`] when the
/// message was changed, and [`Error::InvalidSignature`] for malformed fields.
pub fn verify(raw: &str, key: &VerifyingKey) -> Result<SignatureHeader> {
    let (head, body) = split_head(raw);
    let fields = header_fields(head);
    let candidates: Vec<&Field> = fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("DKIM-Signature"))
        .collect();
    if candidates.is_empty() {
        return Err(Error::MissingSignature);
    }

    // One broken signature must not hide a good one: a message can carry
    // several, from several senders, and only the key's algorithm is ours.
    let mut first_error: Option<Error> = None;
    for field in candidates {
        let signature = match SignatureHeader::parse(field) {
            Ok(signature) => signature,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        if signature.algorithm != key.algorithm() {
            continue;
        }
        match verify_one(&fields, body.as_bytes(), field, &signature, key) {
            Ok(()) => return Ok(signature),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }

    first_error.map_or(Err(Error::NoMatchingSignature), Err)
}

fn verify_one(
    fields: &[Field],
    body: &[u8],
    field: &Field,
    signature: &SignatureHeader,
    key: &VerifyingKey,
) -> Result<()> {
    let canonical_body =
        canonicalize_body(body, signature.body_canonicalization, signature.body_length);
    let computed = Sha256::digest(&canonical_body);
    if computed
        .as_slice()
        .ct_eq(signature.body_hash.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(Error::BodyHashMismatch);
    }

    let stripped = Field {
        name: field.name.clone(),
        raw: strip_b_value(&field.raw)?,
    };
    let input = signing_input(
        fields,
        &signature.signed_headers,
        signature.header_canonicalization,
        &stripped,
    );
    key.verify(&input, &signature.signature)
}

/// Builds the bytes that are hashed: the listed headers plus the signature
/// header itself, the latter without its trailing CRLF.
fn signing_input(
    fields: &[Field],
    names: &[String],
    canonicalization: Canonicalization,
    signature_field: &Field,
) -> Vec<u8> {
    let mut used = vec![false; fields.len()];
    let mut input = Vec::new();
    for name in names {
        // RFC 6376 §5.4.2: instances are consumed from the bottom up, and a
        // name signed more often than it occurs hashes as the empty string.
        let found = fields
            .iter()
            .enumerate()
            .rev()
            .find(|(index, field)| !used[*index] && field.name.eq_ignore_ascii_case(name));
        if let Some((index, field)) = found {
            used[index] = true;
            input.extend_from_slice(&canonicalize_header(field, canonicalization));
            input.extend_from_slice(b"\r\n");
        }
    }
    input.extend_from_slice(&canonicalize_header(signature_field, canonicalization));
    input
}

// ---------------------------------------------------------------------------
// Canonicalization (RFC 6376 §3.4)
// ---------------------------------------------------------------------------

/// One header field: name with its original case, and the raw field text
/// (folds included, no trailing CRLF).
struct Field {
    name: String,
    raw: String,
}

impl Field {
    /// Everything after the first colon.
    fn value(&self) -> &str {
        self.raw.split_once(':').map_or("", |(_, value)| value)
    }
}

fn split_head(raw: &str) -> (&str, &str) {
    let bytes = raw.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let line_end = line_end_at(bytes, offset);
        let line = &raw[offset..line_end.0];
        if line.is_empty() {
            return (&raw[..offset], &raw[line_end.1..]);
        }
        offset = line_end.1;
        if offset == bytes.len() {
            break;
        }
    }
    (raw, "")
}

/// `(end of line content, start of next line)` for the line beginning at
/// `start`, accepting CRLF, LF and CR.
fn line_end_at(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                let next = if bytes.get(index + 1) == Some(&b'\n') {
                    index + 2
                } else {
                    index + 1
                };
                return (index, next);
            }
            b'\n' => return (index, index + 1),
            _ => index += 1,
        }
    }
    (bytes.len(), bytes.len())
}

fn header_fields(head: &str) -> Vec<Field> {
    let bytes = head.as_bytes();
    let mut fields: Vec<Field> = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let (end, next) = line_end_at(bytes, offset);
        let line = &head[offset..end];
        if matches!(line.as_bytes().first(), Some(b' ' | b'\t')) {
            if let Some(last) = fields.last_mut() {
                last.raw.push_str("\r\n");
                last.raw.push_str(line);
            }
        } else if let Some((name, _)) = line.split_once(':') {
            fields.push(Field {
                name: name.trim().to_string(),
                raw: line.to_string(),
            });
        }
        offset = next;
        if next == end && end == bytes.len() {
            break;
        }
    }
    fields
}

/// Canonicalizes one header field into `name:value` form (no trailing CRLF).
fn canonicalize_header(field: &Field, canonicalization: Canonicalization) -> Vec<u8> {
    match canonicalization {
        Canonicalization::Simple => field.raw.as_bytes().to_vec(),
        Canonicalization::Relaxed => {
            let mut out = Vec::with_capacity(field.raw.len());
            out.extend_from_slice(field.name.trim().to_ascii_lowercase().as_bytes());
            out.push(b':');
            let mut pending_space = false;
            let mut started = false;
            for byte in field.value().bytes() {
                match byte {
                    b'\r' | b'\n' => {}
                    b' ' | b'\t' => pending_space = true,
                    _ => {
                        // Leading whitespace after the colon is dropped, any
                        // later run collapses to exactly one space.
                        if pending_space && started {
                            out.push(b' ');
                        }
                        pending_space = false;
                        out.push(byte);
                        started = true;
                    }
                }
            }
            out
        }
    }
}

/// Canonicalizes a body, optionally truncated to `l=` bytes.
///
/// Two linear passes into one output buffer, no per-line `Vec` and no per-line
/// copy: a body that is one newline per byte is valid input (8 MiB of `\n` is
/// still under the parser's body limit), so the work has to stay proportional
/// to the input instead of one allocation per line. Pass one finds where the
/// last non-empty line ends - everything after it is a trailing empty line,
/// dropped per RFC 6376 §3.4.4 - and pass two writes the canonical form of the
/// lines before that straight into `out`.
///
/// The output stays proportional to the input: every retained line contributes
/// its own bytes plus one CRLF, and a line only exists because the input carries
/// at least one terminator byte for it.
fn canonicalize_body(
    body: &[u8],
    canonicalization: Canonicalization,
    length: Option<usize>,
) -> Vec<u8> {
    let mut content_end = 0usize;
    let mut offset = 0usize;
    while offset < body.len() {
        let (end, next) = line_end_at(body, offset);
        if !line_is_empty(&body[offset..end], canonicalization) {
            content_end = next;
        }
        offset = next;
    }

    // `l=` only ever keeps a prefix, so `content_end` bounds both the untruncated
    // length and, with `length`, the wanted one.
    let capacity = length.map_or(content_end, |length| content_end.min(length));
    let mut out = Vec::with_capacity(capacity);

    let mut offset = 0usize;
    while offset < content_end {
        let (end, next) = line_end_at(body, offset);
        match canonicalization {
            Canonicalization::Simple => out.extend_from_slice(&body[offset..end]),
            Canonicalization::Relaxed => {
                let mut pending_space = false;
                for &byte in &body[offset..end] {
                    match byte {
                        b' ' | b'\t' => pending_space = true,
                        _ => {
                            if pending_space {
                                out.push(b' ');
                            }
                            pending_space = false;
                            out.push(byte);
                        }
                    }
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        if length.is_some_and(|length| out.len() >= length) {
            break;
        }
        offset = next;
    }
    if let Some(length) = length {
        out.truncate(length);
    }
    out
}

/// Whether a line carries nothing worth signing: empty under `simple`, and
/// whitespace-only under `relaxed`, which collapses such a line to nothing.
fn line_is_empty(line: &[u8], canonicalization: Canonicalization) -> bool {
    match canonicalization {
        Canonicalization::Simple => line.is_empty(),
        Canonicalization::Relaxed => line.iter().all(|byte| matches!(byte, b' ' | b'\t')),
    }
}

// ---------------------------------------------------------------------------
// DKIM-Signature helpers
// ---------------------------------------------------------------------------

fn pem_label(pem: &str) -> Option<String> {
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                return Some(label.trim().to_string());
            }
        }
    }
    None
}

/// Parses a `tag=value; tag=value` list. Repeated tags are invalid.
fn parse_tags(
    value: &str,
) -> std::result::Result<std::collections::BTreeMap<String, String>, String> {
    let mut tags = std::collections::BTreeMap::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((name, raw_value)) = part.split_once('=') else {
            return Err(format!("tag without '=': {:?}", truncate(part, 40)));
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err("empty tag name".to_string());
        }
        if tags.contains_key(&name) {
            return Err(format!("duplicate {name}= tag"));
        }
        tags.insert(name, raw_value.trim().to_string());
    }
    Ok(tags)
}

fn decode_b64(value: &str, tag: &str) -> Result<Vec<u8>> {
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| Error::InvalidSignature(format!("{tag} is not base64")))
}

/// Empties the `b=` value so the header can be hashed before it exists.
fn strip_b_value(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'=' && is_tag_start(bytes, index) {
            out.push(b'=');
            index += 1;
            // The value may be folded and wrapped; skip it entirely.
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            // A `;` that still separates a following tag belongs to the
            // template; one at the very end was added after signing.
            if index < bytes.len() && !raw[index + 1..].trim().is_empty() {
                out.push(b';');
            }
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out)
        .map_err(|_| Error::InvalidSignature("signature header is not UTF-8".to_string()))
}

/// True when the `=` at `index` closes a `b`/`B` tag.
fn is_tag_start(bytes: &[u8], index: usize) -> bool {
    let Some(name) = index.checked_sub(1).and_then(|at| bytes.get(at)) else {
        return false;
    };
    if !matches!(name, b'b' | b'B') {
        return false;
    }
    let before = index.saturating_sub(2);
    match bytes.get(before) {
        None => true,
        Some(byte) => matches!(byte, b';' | b' ' | b'\t' | b'\r' | b'\n' | b':'),
    }
}

/// `name: value` folded at tag boundaries so lines stay below 78 columns.
fn fold_field(name: &str, value: &str) -> String {
    let mut out = format!("{name}: ");
    let mut line_len = out.len();
    for (index, tag) in value.split_inclusive(';').enumerate() {
        let tag = tag.trim_start();
        let spacer = usize::from(index > 0);
        if index > 0 && line_len + spacer + tag.len() > MAX_LINE {
            out.push_str("\r\n ");
            line_len = 1;
        } else if index > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(tag);
        line_len += tag.len();
    }
    out
}

/// Wraps a long base64 value at 64 columns with folded continuation lines.
fn fold_base64(encoded: &str) -> String {
    const CHUNK: usize = 64;
    let mut out = String::with_capacity(encoded.len() + encoded.len() / CHUNK * 3);
    for (index, chunk) in encoded.as_bytes().chunks(CHUNK).enumerate() {
        if index > 0 {
            out.push_str("\r\n ");
        }
        out.push_str(&String::from_utf8_lossy(chunk));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxed_header_canonicalization_folds_whitespace_and_case() {
        let field = Field {
            name: "SUBJECT".to_string(),
            raw: "SUBJECT:  a   b\t\r\n\t c  ".to_string(),
        };
        assert_eq!(
            canonicalize_header(&field, Canonicalization::Relaxed),
            b"subject:a b c"
        );
        assert_eq!(
            canonicalize_header(&field, Canonicalization::Simple),
            b"SUBJECT:  a   b\t\r\n\t c  "
        );
    }

    #[test]
    fn relaxed_body_strips_trailing_whitespace_and_empty_lines() {
        assert_eq!(
            canonicalize_body(b"a  \r\nb\t\t\r\n\r\n\r\n", Canonicalization::Relaxed, None),
            b"a\r\nb\r\n"
        );
        assert_eq!(
            canonicalize_body(b"a\r\n\r\nb", Canonicalization::Relaxed, None),
            b"a\r\n\r\nb\r\n"
        );
        assert_eq!(canonicalize_body(b"", Canonicalization::Relaxed, None), b"");
        assert_eq!(
            canonicalize_body(b"\r\n\r\n", Canonicalization::Relaxed, None),
            b""
        );
    }

    #[test]
    fn simple_body_keeps_whitespace_and_adds_a_final_crlf() {
        assert_eq!(
            canonicalize_body(b"a  \r\nb", Canonicalization::Simple, None),
            b"a  \r\nb\r\n"
        );
        assert_eq!(
            canonicalize_body(b"a\r\n\r\n\r\n", Canonicalization::Simple, None),
            b"a\r\n"
        );
    }

    #[test]
    fn body_length_truncates_after_canonicalization() {
        assert_eq!(
            canonicalize_body(b"abcdef\r\nghi", Canonicalization::Relaxed, Some(4)),
            b"abcd"
        );
        assert_eq!(
            canonicalize_body(b"abc", Canonicalization::Relaxed, Some(100)),
            b"abc\r\n"
        );
    }

    #[test]
    fn a_line_per_byte_body_does_not_expand() {
        // One newline per byte is valid input and sits under the parser's body
        // limit; every line is empty, so every line is dropped and the output is
        // empty. This is the shape that used to cost one Vec per line.
        let newlines = "\n".repeat(1024 * 1024);
        assert_eq!(
            canonicalize_body(newlines.as_bytes(), Canonicalization::Relaxed, None),
            b""
        );
        assert_eq!(
            canonicalize_body(newlines.as_bytes(), Canonicalization::Simple, None),
            b""
        );

        // One byte of content per line: the output is the content plus the CRLF
        // each line gains, and nothing per line beyond that.
        let lines = "a\n".repeat(256 * 1024);
        let canonical = canonicalize_body(lines.as_bytes(), Canonicalization::Simple, None);
        assert_eq!(canonical.len(), 3 * 256 * 1024);
        assert!(canonical.ends_with(b"\r\n"));
    }

    #[test]
    fn only_trailing_empty_lines_are_dropped() {
        assert_eq!(
            canonicalize_body(
                b"  \r\n\t\r\na\r\n \t\r\n\r\n",
                Canonicalization::Relaxed,
                None
            ),
            b"\r\n\r\na\r\n"
        );
        assert_eq!(
            canonicalize_body(b"\r\n\r\na\r\n\r\n", Canonicalization::Simple, None),
            b"\r\n\r\na\r\n"
        );
        assert_eq!(
            canonicalize_body(b"   ", Canonicalization::Relaxed, None),
            b""
        );
    }

    #[test]
    fn body_length_keeps_a_prefix_of_a_line_dense_body() {
        let lines = "a\n".repeat(64 * 1024);
        let full = canonicalize_body(lines.as_bytes(), Canonicalization::Relaxed, None);
        for length in [0usize, 1, 3, 17, 1024, full.len() - 1] {
            let truncated =
                canonicalize_body(lines.as_bytes(), Canonicalization::Relaxed, Some(length));
            assert_eq!(truncated, full[..length]);
        }
    }

    mod canonicalization_properties {
        use super::*;
        use proptest::prelude::*;

        /// Newlines and whitespace dominate so the generator hits the line-dense
        /// and trailing-empty-line shapes instead of mostly plain text.
        fn body_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(
                prop_oneof![
                    8 => Just(b'a'),
                    3 => Just(b' '),
                    2 => Just(b'\t'),
                    3 => Just(b'\r'),
                    3 => Just(b'\n'),
                    1 => Just(0u8),
                ],
                0..200,
            )
        }

        proptest! {
            #[test]
            fn output_is_crlf_only_and_proportional(body in body_strategy(), simple in any::<bool>()) {
                let canonical = if simple {
                    Canonicalization::Simple
                } else {
                    Canonicalization::Relaxed
                };
                let out = canonicalize_body(&body, canonical, None);
                // Two bytes per retained line, and a line needs a terminator byte
                // in the input, so the output cannot outgrow the input by more
                // than the CRLF that turns a bare LF/CR into a proper terminator.
                prop_assert!(
                    out.len() <= 2 * body.len() + 2,
                    "canonical {} bytes from {} input bytes",
                    out.len(),
                    body.len()
                );
                prop_assert!(out.is_empty() || out.ends_with(b"\r\n"));
                for (index, byte) in out.iter().enumerate() {
                    if *byte == b'\r' {
                        prop_assert_eq!(out.get(index + 1), Some(&b'\n'));
                    } else if *byte == b'\n' {
                        prop_assert_eq!(index.checked_sub(1).and_then(|i| out.get(i)), Some(&b'\r'));
                    }
                }
            }

            #[test]
            fn canonicalization_is_idempotent(body in body_strategy(), simple in any::<bool>()) {
                let canonical = if simple {
                    Canonicalization::Simple
                } else {
                    Canonicalization::Relaxed
                };
                let once = canonicalize_body(&body, canonical, None);
                prop_assert_eq!(canonicalize_body(&once, canonical, None), once);
            }

            #[test]
            fn truncation_is_a_prefix_of_the_full_output(
                body in body_strategy(),
                simple in any::<bool>(),
                length in 0usize..64
            ) {
                let canonical = if simple {
                    Canonicalization::Simple
                } else {
                    Canonicalization::Relaxed
                };
                let full = canonicalize_body(&body, canonical, None);
                if length <= full.len() {
                    prop_assert_eq!(
                        canonicalize_body(&body, canonical, Some(length)),
                        full[..length].to_vec()
                    );
                } else {
                    prop_assert_eq!(canonicalize_body(&body, canonical, Some(length)), full);
                }
            }
        }
    }
    #[test]
    fn strip_b_value_handles_all_layouts() {
        assert_eq!(
            strip_b_value("DKIM-Signature: v=1; bh=x; b=abc;").unwrap(),
            "DKIM-Signature: v=1; bh=x; b="
        );
        assert_eq!(
            strip_b_value("DKIM-Signature: v=1; bh=x; b=abc").unwrap(),
            "DKIM-Signature: v=1; bh=x; b="
        );
        assert_eq!(
            strip_b_value("DKIM-Signature: v=1; b=ab\r\n cd; s=x;").unwrap(),
            "DKIM-Signature: v=1; b=; s=x;"
        );
    }

    #[test]
    fn strip_b_value_leaves_a_header_without_b_alone() {
        assert_eq!(
            strip_b_value("DKIM-Signature: v=1;").unwrap(),
            "DKIM-Signature: v=1;"
        );
    }

    #[test]
    fn header_fields_keep_folds_and_names() {
        let fields = header_fields("A: 1\r\nB: 2\r\n\t3\r\nC:4");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "A");
        assert_eq!(fields[1].raw, "B: 2\r\n\t3");
        assert_eq!(fields[1].value(), " 2\r\n\t3");
        assert_eq!(fields[2].value(), "4");
    }

    #[test]
    fn line_endings_are_accepted_in_every_flavour() {
        let (head, body) = split_head("A: 1\nB: 2\n\nbody");
        assert_eq!(head, "A: 1\nB: 2\n");
        assert_eq!(body, "body");
        let (head, body) = split_head("A: 1\rB: 2\r\rbody");
        assert_eq!(head, "A: 1\rB: 2\r");
        assert_eq!(body, "body");
        let (head, body) = split_head("A: 1");
        assert_eq!(head, "A: 1");
        assert_eq!(body, "");
    }

    #[test]
    fn fold_field_breaks_long_tag_lists() {
        let value = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; h=from:to:subject; bh=AAAA; b=";
        let folded = fold_field("DKIM-Signature", value);
        for line in folded.split("\r\n") {
            assert!(line.len() <= MAX_LINE, "line too long: {line:?}");
        }
        assert!(folded.ends_with("b="));
        // Unfolding gives the input back.
        assert_eq!(
            folded
                .replace("\r\n ", " ")
                .trim_start_matches("DKIM-Signature: "),
            value
        );
    }

    #[test]
    fn fold_base64_keeps_value_intact() {
        let encoded = "A".repeat(200);
        assert_eq!(fold_base64(&encoded).replace("\r\n ", ""), encoded);
    }
}

#[cfg(test)]
mod vector_tests {
    use super::*;

    /// RFC 8463 Appendix A.3 signs `Hi.\r\n\r\nWe lost the game. Are you
    /// hungry yet?\r\n\r\nJoe.\r\n`; the declared body hash is a fixed
    /// point for both canonicalizations.
    #[test]
    fn rfc8463_body_hash_is_reproduced() {
        let raw = include_str!("../tests/fixtures/rfc8463-a3.eml");
        let (_, body) = split_head(raw);
        let expected = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=";
        for canonicalization in [Canonicalization::Simple, Canonicalization::Relaxed] {
            let canonical = canonicalize_body(body.as_bytes(), canonicalization, None);
            assert_eq!(STANDARD.encode(Sha256::digest(&canonical)), expected);
        }
    }

    /// RFC 8463's Ed25519 signature is deterministic: signing the same input
    /// with the same key must reproduce their `b=` byte for byte. That pins
    /// canonicalization, the `h=` instance selection and the
    /// hash-then-sign rule in one assertion.
    #[test]
    fn rfc8463_ed25519_signature_reproduces_exactly() {
        let raw = include_str!("../tests/fixtures/rfc8463-a3.eml");
        let (head, body) = split_head(raw);
        let fields = header_fields(head);
        let field = fields
            .iter()
            .find(|field| field.raw.contains("a=ed25519-sha256"))
            .expect("the Ed25519 signature");
        let signature = SignatureHeader::parse(field).expect("parse");
        let canonical = canonicalize_body(
            body.as_bytes(),
            signature.body_canonicalization,
            signature.body_length,
        );
        assert_eq!(
            Sha256::digest(&canonical).as_slice(),
            signature.body_hash.as_slice()
        );

        let stripped = Field {
            name: field.name.clone(),
            raw: strip_b_value(&field.raw).expect("strip"),
        };
        let input = signing_input(
            &fields,
            &signature.signed_headers,
            signature.header_canonicalization,
            &stripped,
        );

        let key =
            SigningKey::from_ed25519_seed_base64("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
                .expect("seed");
        assert_eq!(key.sign(&input), signature.signature);
    }

    /// `l=` limits how much of the body is signed. A receiver must accept a
    /// message whose tail was appended (mailing lists do it), and must still
    /// reject a change inside the signed prefix.
    #[test]
    fn body_length_limits_what_is_signed() {
        let key = SigningKey::from_ed25519_seed(&[83u8; 32]);
        let rendered = concat!(
            "From: a@example.com\r\n",
            "To: b@example.com\r\n",
            "Subject: s\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: 8bit\r\n",
            "\r\n",
            "signed part. appended later.\r\n",
        );
        let (head, body) = split_head(rendered);
        let fields = header_fields(head);
        let names: Vec<String> = fields.iter().map(|field| field.name.clone()).collect();
        let canonical = canonicalize_body(body.as_bytes(), Canonicalization::Relaxed, Some(12));
        let mut value = format!(
            "v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel; h={}; bh={}; l=12; b=",
            names.join(":"),
            STANDARD.encode(Sha256::digest(&canonical)),
        );
        value = fold_field("DKIM-Signature", &value);
        let signature_field = Field {
            name: "DKIM-Signature".to_string(),
            raw: value.clone(),
        };
        let input = signing_input(&fields, &names, Canonicalization::Relaxed, &signature_field);
        let signature = STANDARD.encode(key.sign(&input));
        let raw = format!("{value}{signature}\r\n{rendered}");

        // As signed: verifies.
        assert!(verify(&raw, &key.verifying_key()).is_ok());
        // Appending after the signed prefix is allowed by `l=`.
        let appended = raw.replace(
            "signed part. appended later.\r\n",
            "signed part. appended later. and more.\r\n",
        );
        assert!(verify(&appended, &key.verifying_key()).is_ok());
        // Changing the signed prefix is not.
        let rewritten = raw.replace("signed part.", "SIGNED PART.");
        assert_eq!(
            verify(&rewritten, &key.verifying_key()).unwrap_err(),
            Error::BodyHashMismatch
        );
    }

    /// A `simple/simple` signing input, written out by hand from RFC 6376
    /// §3.4.1: header fields byte for byte in `h=` order, the signature field
    /// with an empty `b=` last, and no trailing CRLF.
    #[test]
    fn simple_signing_input_is_byte_exact() {
        let raw = concat!(
            "From: a@example.com\r\n",
            "To: b@example.com\r\n",
            "Subject: hi\r\n",
            "\r\n",
            "body\r\n",
        );
        let (head, _) = split_head(raw);
        let fields = header_fields(head);
        let signature = Field {
            name: "DKIM-Signature".to_string(),
            raw: "DKIM-Signature: v=1; b=".to_string(),
        };
        let names = vec!["from".to_string(), "to".to_string(), "subject".to_string()];
        let input = signing_input(&fields, &names, Canonicalization::Simple, &signature);
        assert_eq!(
            input,
            b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\nDKIM-Signature: v=1; b="
        );
    }

    /// `relaxed` lowercases the name, unfolds, collapses WSP and drops the
    /// space after the colon (RFC 6376 §3.4.2).
    #[test]
    fn relaxed_signing_input_is_byte_exact() {
        let raw = concat!("SUBJECT:\t  Grüße\r\n", " from  \r\n", "\r\n", "body",);
        let (head, _) = split_head(raw);
        let fields = header_fields(head);
        let signature = Field {
            name: "DKIM-Signature".to_string(),
            raw: "DKIM-Signature: b=".to_string(),
        };
        let input = signing_input(
            &fields,
            &["subject".to_string()],
            Canonicalization::Relaxed,
            &signature,
        );
        assert_eq!(
            String::from_utf8(input).expect("utf-8"),
            "subject:Grüße from\r\ndkim-signature:b="
        );
    }
}
