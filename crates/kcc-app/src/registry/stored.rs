//! Where a profile's credentials live: kcc-managed sealed records or operator files.

use std::path::Path;

use kcc_rci::auth::Credentials;
use secrecy::{ExposeSecret as _, SecretString};

use super::{ManagedRouterProfile, ProfileSource, RegistryError, auth};
use crate::{
    credentials::{CredentialKind, CredentialStore},
    persist::write_atomic,
};

/// The secret behind `path`: the sealed record when `path` is the managed path of
/// `router`'s credential of `kind`, else the operator file (refused when others can
/// read it).
///
/// # Errors
/// [`RegistryError`] when the sealed record or the operator file cannot be read or opened.
pub(super) fn secret(
    credentials: Option<&CredentialStore>,
    router: &str,
    kind: CredentialKind,
    path: &Path,
) -> Result<SecretString, RegistryError> {
    if let Some(store) = credentials
        && store.manages(router, kind, path)?
    {
        return Ok(store.open(router, kind)?);
    }
    auth::secret_file(path)
}

/// Stores `credential` as the new primary password of `profile`.
///
/// A state profile with a credential store, or any profile already pointing at its
/// sealed record, gets the password sealed and points at the record; the profile's
/// external file is left as it was. Any other password profile gets its own
/// `password_file` rewritten (owner-only). A token profile stores nothing.
///
/// # Errors
/// [`RegistryError`] when the password cannot be sealed or the file cannot be written.
pub(super) fn replace_password(
    credentials: Option<&CredentialStore>,
    source: ProfileSource,
    profile: &mut ManagedRouterProfile,
    credential: &Credentials,
) -> Result<(), RegistryError> {
    let Some(file) = profile.password_file.clone() else {
        return Ok(());
    };
    match credentials {
        Some(store)
            if matches!(source, ProfileSource::State)
                || store.manages(&profile.id, CredentialKind::Password, &file)? =>
        {
            store.store(&profile.id, CredentialKind::Password, &credential.password)?;
            profile.password_file = Some(store.sealed_path(&profile.id, CredentialKind::Password)?);
        }
        Some(_) | None => {
            let invalid = |reason: &str| RegistryError::InvalidProfile {
                reason: reason.to_owned(),
            };
            let parent = file
                .parent()
                .ok_or_else(|| invalid("credential file has no parent"))?;
            let name = file
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("credential file has no name"))?;
            write_atomic(parent, name, credential.password.expose_secret().as_bytes())?;
        }
    }
    profile.login.clone_from(&credential.login);
    Ok(())
}
