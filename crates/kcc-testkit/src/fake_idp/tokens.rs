//! The fake provider's signing keys, the tokens they sign and the forgeries.

use core::{fmt, ops::Range};
use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    error::Unspecified,
    hmac,
    rand::{SecureRandom as _, SystemRandom},
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _},
};
use serde_json::{Map, Value, json};

/// A signing algorithm of the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// ECDSA over P-256 with SHA-256 (`ES256`).
    Es256,
    /// Ed25519 (`EdDSA`).
    EdDsa,
}

/// A token a resource server must refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Forgery {
    /// `HS256`, keyed with the served ES256 public key's bytes (algorithm confusion).
    Hs256WithPublicKey,
    /// `alg: none` and an empty signature.
    AlgNone,
    /// An `RS256` header naming the served ES256 key, signed by it.
    Rs256Header,
    /// ES256 by a key the provider does not serve, under the served key's id.
    ForeignKeySameKid,
}

/// The claims of a token; absent ones are left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Claims {
    /// `iss`.
    pub iss: Option<String>,
    /// `aud`.
    pub aud: Option<String>,
    /// `azp`, the authorized party.
    pub azp: Option<String>,
    /// `sub`.
    pub sub: Option<String>,
    /// `preferred_username`.
    pub preferred_username: Option<String>,
    /// `exp`, Unix seconds.
    pub exp: Option<u64>,
    /// `nbf`, Unix seconds.
    pub nbf: Option<u64>,
    /// `groups`.
    pub groups: Option<Vec<String>>,
    /// `scope`, space-separated.
    pub scope: Option<String>,
}

impl Claims {
    /// Claims for `sub` issued by `iss` to `aud`, valid until `exp`.
    #[inline]
    #[must_use]
    pub fn new(iss: &str, aud: &str, sub: &str, exp: u64) -> Self {
        Self {
            iss: Some(iss.to_owned()),
            aud: Some(aud.to_owned()),
            sub: Some(sub.to_owned()),
            exp: Some(exp),
            ..Self::default()
        }
    }

    /// The JSON payload.
    fn payload(&self) -> Value {
        let mut claims = Map::new();
        let texts = [
            ("iss", &self.iss),
            ("aud", &self.aud),
            ("azp", &self.azp),
            ("sub", &self.sub),
            ("preferred_username", &self.preferred_username),
            ("scope", &self.scope),
        ];
        for (name, value) in texts {
            if let Some(text) = value {
                drop(claims.insert(name.to_owned(), Value::String(text.clone())));
            }
        }
        for (name, value) in [("exp", self.exp), ("nbf", self.nbf)] {
            if let Some(seconds) = value {
                drop(claims.insert(name.to_owned(), Value::from(seconds)));
            }
        }
        if let Some(groups) = &self.groups {
            drop(claims.insert("groups".to_owned(), json!(groups)));
        }
        Value::Object(claims)
    }
}

/// The served keys.
pub(super) struct KeySet {
    /// The ES256 key and its id.
    es256: (EcdsaKeyPair, String),
    /// The Ed25519 key and its id.
    eddsa: (Ed25519KeyPair, String),
    /// The random source of ECDSA signatures.
    random: SystemRandom,
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("es256", &self.es256.1)
            .field("eddsa", &self.eddsa.1)
            .finish_non_exhaustive()
    }
}

impl KeySet {
    /// Two fresh keys under fresh ids.
    ///
    /// # Errors
    ///
    /// The key generation failed.
    pub(super) fn generate() -> io::Result<Self> {
        let random = SystemRandom::new();
        let es256 = (ecdsa_key(&random)?, key_id(&random)?);
        let document = Ed25519KeyPair::generate_pkcs8(&random).map_err(unspecified)?;
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|_rejected| io::Error::other("Ed25519 key rejected"))?;
        let eddsa = (pair, key_id(&random)?);
        Ok(Self {
            es256,
            eddsa,
            random,
        })
    }

    /// The JWKS document of both keys.
    pub(super) fn jwks(&self) -> Value {
        let point = self.es256.0.public_key().as_ref();
        let coordinate =
            |range: Range<usize>| URL_SAFE_NO_PAD.encode(point.get(range).unwrap_or_default());
        json!({ "keys": [
            {
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                "kid": self.es256.1, "x": coordinate(1..33), "y": coordinate(33..65),
            },
            {
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                "kid": self.eddsa.1,
                "x": URL_SAFE_NO_PAD.encode(self.eddsa.0.public_key().as_ref()),
            },
        ]})
    }

    /// `claims` signed by the served key of `algorithm`.
    ///
    /// # Errors
    ///
    /// The signature failed.
    pub(super) fn sign(&self, algorithm: Algorithm, claims: &Claims) -> io::Result<String> {
        match algorithm {
            Algorithm::Es256 => {
                let input = signing_input("ES256", Some(&self.es256.1), claims);
                let signature = self.es256_signature(&self.es256.0, &input)?;
                Ok(joined(&input, &signature))
            }
            Algorithm::EdDsa => {
                let input = signing_input("EdDSA", Some(&self.eddsa.1), claims);
                let signature = self.eddsa.0.sign(input.as_bytes());
                Ok(joined(&input, signature.as_ref()))
            }
        }
    }

    /// The token `forgery` describes for `claims`.
    ///
    /// # Errors
    ///
    /// A key or a signature failed.
    pub(super) fn forge(&self, forgery: Forgery, claims: &Claims) -> io::Result<String> {
        let kid = Some(self.es256.1.as_str());
        match forgery {
            Forgery::Hs256WithPublicKey => {
                let input = signing_input("HS256", kid, claims);
                let key = hmac::Key::new(hmac::HMAC_SHA256, self.es256.0.public_key().as_ref());
                Ok(joined(&input, hmac::sign(&key, input.as_bytes()).as_ref()))
            }
            Forgery::AlgNone => Ok(joined(&signing_input("none", None, claims), &[])),
            Forgery::Rs256Header => {
                let input = signing_input("RS256", kid, claims);
                Ok(joined(
                    &input,
                    &self.es256_signature(&self.es256.0, &input)?,
                ))
            }
            Forgery::ForeignKeySameKid => {
                let foreign = ecdsa_key(&self.random)?;
                let input = signing_input("ES256", kid, claims);
                Ok(joined(&input, &self.es256_signature(&foreign, &input)?))
            }
        }
    }

    /// The fixed-size `r || s` ES256 signature of `input` by `key`.
    ///
    /// # Errors
    ///
    /// The signature failed.
    fn es256_signature(&self, key: &EcdsaKeyPair, input: &str) -> io::Result<Vec<u8>> {
        Ok(key
            .sign(&self.random, input.as_bytes())
            .map_err(unspecified)?
            .as_ref()
            .to_vec())
    }
}

/// A fresh ES256 key.
///
/// # Errors
///
/// The key generation failed.
fn ecdsa_key(random: &SystemRandom) -> io::Result<EcdsaKeyPair> {
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, random)
        .map_err(unspecified)?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), random)
        .map_err(|_rejected| io::Error::other("ES256 key rejected"))
}

/// A fresh key id: 16 random bytes, hex.
///
/// # Errors
///
/// The random source failed.
fn key_id(random: &SystemRandom) -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes).map_err(unspecified)?;
    Ok(bytes
        .iter()
        .flat_map(|byte| [byte >> 4_u8, byte & 0x0f])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect())
}

/// `base64url(header).base64url(payload)` with the header `{"alg", "typ": "JWT", "kid"}`.
fn signing_input(algorithm: &str, kid: Option<&str>, claims: &Claims) -> String {
    let mut header = json!({ "alg": algorithm, "typ": "JWT" });
    if let (Some(id), Some(fields)) = (kid, header.as_object_mut()) {
        drop(fields.insert("kid".to_owned(), Value::String(id.to_owned())));
    }
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.payload().to_string())
    )
}

/// The compact token of `input` and `signature`.
fn joined(input: &str, signature: &[u8]) -> String {
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// `ring`'s opaque failure as an I/O error.
fn unspecified(_failure: Unspecified) -> io::Error {
    io::Error::other("ring failed")
}
