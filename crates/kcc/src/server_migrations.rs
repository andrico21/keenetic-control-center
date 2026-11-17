//! The startup warning of routers whose password still sits in an external plaintext file.

use kcc_app::registry::{RegistryError, RouterRegistry};

/// Logs one warning per Web UI or CLI router that still reads its password from an
/// external plaintext file, naming the command that seals it. The file is left alone.
///
/// # Errors
/// Returns a registry error when the profiles cannot be listed.
pub(super) fn warn_external_password_files(registry: &RouterRegistry) -> Result<(), RegistryError> {
    for (router, file) in registry.external_password_files()? {
        tracing::warn!(
            router = %router,
            file = %file.display(),
            "router {router} reads its password from an external plaintext file; seal it with `kcc router edit {router} --new-password --password-file {}`",
            file.display()
        );
    }
    Ok(())
}
