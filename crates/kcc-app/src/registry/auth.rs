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

/// Checks that a profile names exactly one credential file and that it fits the scheme.
pub(super) fn validate(profile: &ManagedRouterProfile) -> Result<(), RegistryError> {
    let reason = match (&profile.password_file, &profile.token_file) {
        (Some(_), None) if profile.auth == RouterAuth::Token => {
            "auth = \"token\" requires token_file"
        }
        (Some(_), None) if profile.login.is_empty() => "login must not be empty",
        (None, Some(_)) if profile.auth != RouterAuth::Token => {
            "token_file requires auth = \"token\""
        }
        (Some(_), None) | (None, Some(_)) => return Ok(()),
        (Some(_), Some(_)) | (None, None) => "set exactly one of password_file and token_file",
    };
    Err(RegistryError::InvalidProfile {
        reason: reason.to_owned(),
    })
}

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
pub(super) fn secret_file(file: &Path) -> Result<SecretString, RegistryError> {
    read_secret_file(file).map_err(|error| match error {
        SecretFileError::Read { path, source } => RegistryError::CredentialFile { path, source },
        SecretFileError::Permissions { path } => RegistryError::CredentialPermissions { path },
    })
}
