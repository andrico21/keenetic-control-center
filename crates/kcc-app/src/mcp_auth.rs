//! kcc's own OAuth 2.1 authorization server for MCP clients: the parts that hold state.
//!
//! - [`signing`]: the Ed25519 key (ring) that signs access tokens as compact JWS
//!   (RFC 9068 `at+jwt`), sealed at `<state>/mcp/oauth-signing.sealed`, and its JWKS. One
//!   key serves the state directory for its whole life: there is no key rotation.
//! - [`clients`]: the public clients (RFC 7591 dynamic registration or an admin's
//!   pre-registration) in `mcp_oauth_clients.json`, their redirect URI rules (RFC 8252
//!   7.1/7.3) and kcc's per-address registration limiter, which keeps addresses in memory
//!   only.
//! - [`pending`]: authorization requests awaiting consent and the authorization codes
//!   issued for them, in memory only, single use, bound to client, redirect URI,
//!   resource and PKCE S256 challenge (RFC 7636).
//! - [`grants`]: one grant per consented connection in `mcp_oauth_grants.json`, with its
//!   rotating refresh token kept as a SHA-256 hash; reuse of a rotated token revokes the
//!   whole family (RFC 9700 4.14).
//! - [`verify`]: the per-call check of a grant and the reading of the `kcc_grant` claim.
//!
//! Every token, code and request id is 32 bytes from the OS RNG; ids are 64 lowercase
//! hex digits, secrets 43 base64url characters. Secrets are compared in constant time,
//! looked up by scanning every stored entry, and held in [`SecretString`]s, so no
//! `Debug` output shows one. Access tokens and codes are never written to disk; client
//! addresses never are either. Every operation here is synchronous file or memory work:
//! async callers run it on a blocking thread.

pub mod clients;
pub mod grants;
pub mod pending;
pub mod signing;
pub mod verify;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom as _, SystemRandom};
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Random bytes in every id, token and code (256 bits).
const RANDOM_BYTES: usize = 32;

/// The OS random number generator failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the OS random number generator failed")]
#[non_exhaustive]
pub struct RandomError;

/// 32 bytes from the OS RNG.
///
/// # Errors
///
/// [`RandomError`] when the OS RNG fails.
fn random() -> Result<[u8; RANDOM_BYTES], RandomError> {
    let mut bytes = [0_u8; RANDOM_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_unspecified| RandomError)?;
    Ok(bytes)
}

/// A new random id: 64 lowercase hex digits.
///
/// # Errors
///
/// [`RandomError`] when the OS RNG fails.
fn new_id() -> Result<String, RandomError> {
    Ok(hex(&random()?))
}

/// A new random secret: 43 base64url characters without padding.
///
/// # Errors
///
/// [`RandomError`] when the OS RNG fails.
fn new_secret() -> Result<SecretString, RandomError> {
    Ok(SecretString::from(URL_SAFE_NO_PAD.encode(random()?)))
}

/// The SHA-256 of `bytes` as 64 lowercase hex digits.
fn digest_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4_u8, byte & 0x0f])
        .filter_map(|nibble| DIGITS.get(usize::from(nibble)).copied().map(char::from))
        .collect()
}

/// Whether `left` and `right` are equal, in time independent of where they differ.
fn same(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

/// Whether `id` has the shape of an id this module creates.
fn is_id(id: &str) -> bool {
    id.len() == RANDOM_BYTES.saturating_mul(2)
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
