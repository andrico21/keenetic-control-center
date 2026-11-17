//! Authentication scheme and credential source of a router profile.

use std::path::Path;

use kcc_rci::auth_options::{Mode, Options};
use secrecy::SecretString;

use super::{CredentialUse, ManagedRouterProfile, RegistryError, stored};
use crate::{
    credentials::{CredentialKind, CredentialStore},
    secrets::files::{SecretFileError, read_secret_file},
    settings::RouterAuth,
};

/// The RCI authentication policy of sign-in mode `auth`, without a token.
pub(super) fn mode_options(auth: RouterAuth) -> Options {
    let mut options = Options::default();
    options.mode = match auth {
        RouterAuth::Auto | RouterAuth::Token => Mode::Auto,
        RouterAuth::Ndw2 => Mode::Ndw2,
        RouterAuth::Ndw4 => Mode::Ndw4,
        RouterAuth::Digest => Mode::DigestProxy,
    };
    options
}

/// Builds the RCI authentication policy; only the primary credential pair uses the token,
/// opened from its sealed record when the profile points there.
///
/// # Errors
/// [`RegistryError`] when the token cannot be read or opened.
pub(super) fn options(
    store: Option<&CredentialStore>,
    profile: &ManagedRouterProfile,
    credential_use: CredentialUse,
) -> Result<Options, RegistryError> {
    let mut options = mode_options(profile.auth);
    if matches!(credential_use, CredentialUse::Primary)
        && let Some(path) = &profile.token_file
    {
        options.experimental_token = Some(stored::secret(
            store,
            &profile.id,
            CredentialKind::Token,
            path,
        )?);
    }
    Ok(options)
}

/// Reads one operator-managed secret file, dropping its trailing line break; refuses a
/// file group or others can read.
///
/// # Errors
/// [`RegistryError::CredentialFile`] when the file cannot be read,
/// [`RegistryError::CredentialPermissions`] when group or others can read it.
pub(super) fn secret_file(file: &Path) -> Result<SecretString, RegistryError> {
    read_secret_file(file).map_err(|error| match error {
        SecretFileError::Read { path, source } => RegistryError::CredentialFile { path, source },
        SecretFileError::Permissions { path } => RegistryError::CredentialPermissions { path },
    })
}
