//! The identity provider's CA bundle of the MCP listeners' external OIDC sign-in, uploaded
//! on the Web and stored as `<state>/mcp/oidc-ca.pem`.
//!
//! The bundle decides which TLS certificate kcc trusts when it fetches the JWKS that
//! validates the provider's tokens, so it is checked exactly like the client CA
//! ([`check_mtls_ca`]): at most 64 KiB of PEM holding one to ten CA certificates and
//! nothing else, framed so the MCP listeners' PEM reader loads the same certificates.
//! It is stored the same way (atomic rename, `0644` on Unix).

use std::path::PathBuf;

use super::client_ca::{CaError, DIRECTORY, check_mtls_ca, read_as, restored_as, stored_as};
use crate::persist::StateStore;

/// The identity provider's CA bundle file name.
pub const OIDC_CA: &str = "oidc-ca.pem";

/// The stored identity provider CA bundle of `store`.
#[inline]
#[must_use]
pub fn oidc_ca_path(store: &StateStore) -> PathBuf {
    store.dir().join(DIRECTORY).join(OIDC_CA)
}

/// Checks `pem` as an identity provider CA bundle, with the client CA's rules; the
/// subjects of its certificates, in file order.
///
/// # Errors
///
/// A [`CaError`] other than [`CaError::State`] naming the first rule the file breaks.
#[inline]
pub fn check_oidc_ca(pem: &[u8]) -> Result<Vec<String>, CaError> {
    check_mtls_ca(pem)
}

/// Checks `pem` ([`check_oidc_ca`]) and stores it as the identity provider CA bundle,
/// replacing the previous one atomically; a refused file is never written.
///
/// # Errors
///
/// The [`CaError`] of the check; [`CaError::State`] when the file cannot be written.
#[inline]
pub fn store_oidc_ca(store: &StateStore, pem: &[u8]) -> Result<Vec<String>, CaError> {
    stored_as(store, OIDC_CA, pem)
}

/// Puts `previous` back as the identity provider CA bundle unchecked, or removes the file
/// when there was none: undoes a [`store_oidc_ca`] whose listeners could not use it.
///
/// # Errors
///
/// [`CaError::State`] when the file cannot be written or removed.
#[inline]
pub fn restore_oidc_ca(store: &StateStore, previous: Option<&[u8]>) -> Result<(), CaError> {
    restored_as(store, OIDC_CA, previous)
}

/// The stored identity provider CA bundle as it is, unchecked; `None` when none is
/// stored.
///
/// # Errors
///
/// [`CaError::State`] when the file cannot be read.
#[inline]
pub fn read_oidc_ca(store: &StateStore) -> Result<Option<Vec<u8>>, CaError> {
    read_as(&oidc_ca_path(store))
}

/// The subjects of the stored bundle's certificates; `None` when none is stored.
///
/// # Errors
///
/// The stored file breaks a rule of [`check_oidc_ca`] or cannot be read.
#[inline]
pub fn oidc_ca_subjects(store: &StateStore) -> Result<Option<Vec<String>>, CaError> {
    read_oidc_ca(store)?
        .map(|bytes| check_oidc_ca(&bytes))
        .transpose()
}
