//! The `[server] tls_key_path` permission check, run before the key reaches the listener.

use fluent_bundle::FluentArgs;
use kcc_app::{
    secrets::files::{SecretFileError, open_secret_file},
    settings::Config,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::server::{ServerError, error};

/// Refuses a TLS private key that group or others can read (unix only).
///
/// # Errors
///
/// Returns the localized refusal naming the key, or the key's read failure.
pub(crate) fn check(config: &Config) -> Result<(), ServerError> {
    let Some(key) = &config.server.tls_key_path else {
        return Ok(());
    };
    match open_secret_file(key) {
        Ok(file) => {
            drop(file);
            Ok(())
        }
        Err(SecretFileError::Permissions { path }) => {
            let mut args = FluentArgs::new();
            args.set("path", path.display().to_string());
            Err(error(tr(
                Locale::En,
                keys::ERRORS_SECRET_FILE_PERMISSIONS,
                Some(&args),
            )))
        }
        Err(other @ (SecretFileError::Read { path: _, source: _ } | _)) => Err(error(other)),
    }
}
