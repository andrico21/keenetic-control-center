//! The `[server] tls_key_path` permission check, run before the key reaches the listener.

use std::{fs::File, path::Path};

use fluent_bundle::FluentArgs;
use kcc_app::{
    secrets::files::{SecretFileError, open_secret_file},
    settings::Config,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::server_error::ServerError;

/// Refuses a TLS private key that group or others can read (unix only).
///
/// # Errors
///
/// Returns [`ServerError::TlsKeyReadable`] naming the key, or the key's read failure.
pub(crate) fn check(config: &Config) -> Result<(), ServerError> {
    let Some(key) = &config.server.tls_key_path else {
        return Ok(());
    };
    drop(open_key(key)?);
    Ok(())
}

/// Opens the TLS private key at `key`, refusing one that group or others can read (unix
/// only).
///
/// # Errors
///
/// Returns [`ServerError::TlsKeyReadable`] naming the key, or the key's read failure.
pub(crate) fn open_key(key: &Path) -> Result<File, ServerError> {
    match open_secret_file(key) {
        Ok(file) => Ok(file),
        Err(SecretFileError::Permissions { path }) => Err(ServerError::TlsKeyReadable { path }),
        Err(other @ (SecretFileError::Read { path: _, source: _ } | _)) => Err(other.into()),
    }
}

/// The refusal of a key file at `path` that group or others can read.
pub(crate) fn readable(path: &Path) -> String {
    let mut args = FluentArgs::new();
    args.set("path", path.display().to_string());
    tr(
        Locale::En,
        keys::ERRORS_SECRET_FILE_PERMISSIONS,
        Some(&args),
    )
}
