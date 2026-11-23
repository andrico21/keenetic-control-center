//! The Ed25519 key that signs kcc's MCP access tokens, its JWKS and the tokens themselves.
//!
//! The key is generated with ring on first use and its PKCS#8 v2 document is sealed with
//! the master key under `mcp:oauth-signing` at `<state>/mcp/oauth-signing.sealed`. A
//! record that cannot be opened (another master key, tampering) is an error, never a
//! reason to make a new key. There is no rotation: the key, and its `kid` (the RFC 7638
//! thumbprint), stay for the life of the state directory.
//!
//! An access token is the compact JWS `base64url(header).base64url(claims).base64url(sig)`
//! with the header `{"alg":"EdDSA","typ":"at+jwt","kid":..}` and the RFC 9068 claims
//! `iss`, `sub`, `aud`, `client_id`, `scope`, `kcc_grant`, `iat`, `exp` and `jti`.

use core::{fmt, time::Duration};
use std::{fs, io, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{RandomError, grants::Grant, new_secret};
use crate::{
    persist::{StateError, StateStore, create_private_dir, io_error, write_exclusive},
    secrets::{CryptoError, MasterKey, SealedSecret, binding::Binding},
};

/// Directory of the sealed key below the state directory.
const DIR: &str = "mcp";
/// File name of the sealed key.
const FILE: &str = "oauth-signing.sealed";
/// State lock serializing the creation of the key.
const LOCK: &str = "mcp-oauth-signing";
/// Current key record schema; records of any other schema are refused.
const SCHEMA: u32 = 1;
/// The JOSE algorithm of every token.
const ALGORITHM: &str = "EdDSA";
/// The only scope a kcc access token carries.
const SCOPE: &str = "mcp";

/// A failure loading, creating or using the signing key. Never carries key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers name it beside the other mcp_auth errors"
)]
pub enum SigningError {
    /// State locking or filesystem persistence failed.
    #[error("signing key storage failed")]
    State(#[source] StateError),
    /// Sealing or opening the key failed (another master key or a tampered record).
    #[error("signing key encryption failed")]
    Crypto(#[source] CryptoError),
    /// The OS random number generator failed.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The sealed record has another schema or shape, or a token part did not serialize.
    #[error("the signing key record is invalid")]
    Record,
    /// The opened key is not an Ed25519 PKCS#8 v2 document.
    #[error("the signing key is not an Ed25519 key")]
    Key,
}

impl From<StateError> for SigningError {
    #[inline]
    fn from(source: StateError) -> Self {
        Self::State(source)
    }
}

impl From<CryptoError> for SigningError {
    #[inline]
    fn from(source: CryptoError) -> Self {
        Self::Crypto(source)
    }
}

/// One versioned sealed key record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    /// Record schema.
    schema: u32,
    /// The sealed base64url PKCS#8 document.
    sealed: SealedSecret,
}

/// When a token was issued and when it expires, in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Validity {
    /// `iat`.
    issued_at: u64,
    /// `exp`.
    expires_at: u64,
}

impl Validity {
    /// A token issued at `issued_at` (Unix seconds) that lives `lifetime`.
    #[inline]
    #[must_use]
    pub const fn new(issued_at: u64, lifetime: Duration) -> Self {
        Self {
            issued_at,
            expires_at: issued_at.saturating_add(lifetime.as_secs()),
        }
    }
}

/// The claims of one access token for a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccessClaims {
    /// `iss`: the kcc issuer.
    issuer: String,
    /// `sub`: the account.
    subject: String,
    /// `aud`: the canonical MCP resource.
    audience: String,
    /// `client_id`.
    client_id: String,
    /// `kcc_grant`: the grant id.
    grant: String,
    /// `iat` and `exp`.
    validity: Validity,
}

impl AccessClaims {
    /// The claims of a token for `grant`, issued by `issuer`, valid for `validity`.
    #[inline]
    #[must_use]
    pub fn new(issuer: &str, grant: &Grant, validity: Validity) -> Self {
        Self {
            issuer: issuer.to_owned(),
            subject: grant.account().to_owned(),
            audience: grant.resource().to_owned(),
            client_id: grant.client().to_owned(),
            grant: grant.id().to_owned(),
            validity,
        }
    }
}

/// The JWS payload: the claims plus the scope and a random `jti`.
#[derive(Serialize)]
struct Payload<'claims> {
    /// Issuer.
    iss: &'claims str,
    /// Account.
    sub: &'claims str,
    /// Resource.
    aud: &'claims str,
    /// Client.
    client_id: &'claims str,
    /// Always [`SCOPE`].
    scope: &'static str,
    /// Grant id.
    kcc_grant: &'claims str,
    /// Issued at.
    iat: u64,
    /// Expires at.
    exp: u64,
    /// 256 random bits.
    jti: &'claims str,
}

/// The signing key. `Debug` shows its `kid` only.
#[expect(
    clippy::module_name_repetitions,
    reason = "the name the authorization server uses for its key"
)]
pub struct SigningKey {
    /// The key pair.
    pair: Ed25519KeyPair,
    /// base64url of the 32-byte public key.
    x: String,
    /// RFC 7638 thumbprint of the public JWK.
    kid: String,
}

impl fmt::Debug for SigningKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Opens the sealed key of `state`, creating and sealing a new one when there is none.
    ///
    /// # Errors
    ///
    /// [`SigningError::Crypto`] when the record does not open with `key` (it is then left
    /// as it is), [`SigningError::Record`] or [`SigningError::Key`] for a damaged record,
    /// or a storage or RNG failure.
    #[inline]
    pub fn load_or_create(state: &StateStore, key: &MasterKey) -> Result<Self, SigningError> {
        let dir = state.dir().join(DIR);
        if let Some(found) = load(&dir, key)? {
            return Ok(found);
        }
        let _lock = state.lock(LOCK)?;
        if let Some(found) = load(&dir, key)? {
            return Ok(found);
        }
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_unspecified| RandomError)?;
        let text = SecretString::from(URL_SAFE_NO_PAD.encode(pkcs8.as_ref()));
        let record = KeyRecord {
            schema: SCHEMA,
            sealed: key.seal(&Binding::mcp_oauth_signing(), &text)?,
        };
        let mut bytes =
            serde_json::to_vec_pretty(&record).map_err(|_error| SigningError::Record)?;
        bytes.push(b'\n');
        create_private_dir(&dir)?;
        if !write_exclusive(&dir, FILE, &bytes)? {
            return load(&dir, key)?.ok_or(SigningError::Record);
        }
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// The key id every token header and the JWKS carry.
    #[inline]
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The JWKS: `{"keys":[{"kty":"OKP","crv":"Ed25519","x":..,"kid":..,"alg":"EdDSA","use":"sig"}]}`.
    #[inline]
    #[must_use]
    pub fn jwks(&self) -> Value {
        json!({"keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self.x,
            "kid": self.kid,
            "alg": ALGORITHM,
            "use": "sig",
        }]})
    }

    /// Signs an access token with `claims`, a fresh `jti` and the scope `mcp`.
    ///
    /// # Errors
    ///
    /// [`SigningError::Random`] when the OS RNG fails, [`SigningError::Record`] when a
    /// part does not serialize.
    #[inline]
    pub fn mint_access(&self, claims: &AccessClaims) -> Result<SecretString, SigningError> {
        let jti = new_secret()?;
        let header = json!({"alg": ALGORITHM, "typ": "at+jwt", "kid": self.kid});
        let payload = Payload {
            iss: &claims.issuer,
            sub: &claims.subject,
            aud: &claims.audience,
            client_id: &claims.client_id,
            scope: SCOPE,
            kcc_grant: &claims.grant,
            iat: claims.validity.issued_at,
            exp: claims.validity.expires_at,
            jti: jti.expose_secret(),
        };
        let header_json = serde_json::to_vec(&header).map_err(|_error| SigningError::Record)?;
        let payload_json = serde_json::to_vec(&payload).map_err(|_error| SigningError::Record)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header_json),
            URL_SAFE_NO_PAD.encode(payload_json)
        );
        let signature = self.pair.sign(input.as_bytes());
        Ok(SecretString::from(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )))
    }

    /// The key of the PKCS#8 v2 document `pkcs8`.
    ///
    /// # Errors
    ///
    /// [`SigningError::Key`] for anything but an Ed25519 PKCS#8 v2 document.
    fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, SigningError> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_rejected| SigningError::Key)?;
        let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
        let thumbprint = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes()));
        Ok(Self { pair, x, kid })
    }
}

/// Opens the sealed key in `dir`; `None` when there is none.
///
/// # Errors
///
/// As [`SigningKey::load_or_create`].
fn load(dir: &Path, key: &MasterKey) -> Result<Option<SigningKey>, SigningError> {
    let path = dir.join(FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(&path, error).into()),
    };
    let record: KeyRecord =
        serde_json::from_slice(&bytes).map_err(|_error| SigningError::Record)?;
    if record.schema != SCHEMA {
        return Err(SigningError::Record);
    }
    let text = key.open(&Binding::mcp_oauth_signing(), &record.sealed)?;
    let pkcs8 = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(text.expose_secret())
            .map_err(|_error| SigningError::Record)?,
    );
    SigningKey::from_pkcs8(&pkcs8).map(Some)
}
