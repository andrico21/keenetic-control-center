//! The self-signed certificate of the dedicated MCP listener (`[mcp.dedicated] tls =
//! "self_signed"`), generated once into the state directory.

use core::fmt::Display;
use std::path::{Path, PathBuf};

use kcc_app::{persist::write_atomic, settings::mcp_schema::DedicatedListenerConfig};

use crate::cli::files::private_dir;

/// The state subdirectory holding the dedicated listener's certificate and key.
const DIRECTORY: &str = "mcp";

/// The certificate file name.
const CERT_FILE: &str = "dedicated-cert.pem";

/// The private key file name (owner-only).
const KEY_FILE: &str = "dedicated-key.pem";

/// Why the certificate could not be generated or written.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SelfSignedError {
    /// The certificate could not be generated.
    #[error("cannot generate the dedicated listener's certificate: {0}")]
    Generate(String),
    /// The state subdirectory or a file could not be written.
    #[error("cannot write the dedicated listener's certificate: {0}")]
    Write(String),
}

/// The paths of the certificate and key below `state_dir`, generating both when either is
/// missing, for `localhost`, the bind address and the host of `public_url`.
///
/// The key is written owner-only; the caller opens it through the TLS key permission
/// check, which refuses a key that group or others can read.
///
/// # Errors
///
/// [`SelfSignedError`] when generating or writing fails.
pub(crate) fn ensure(
    state_dir: &Path,
    dedicated: &DedicatedListenerConfig,
) -> Result<(PathBuf, PathBuf), SelfSignedError> {
    let dir = state_dir.join(DIRECTORY);
    let (cert, key) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
    if cert.is_file() && key.is_file() {
        return Ok((cert, key));
    }
    let mut names = vec!["localhost".to_owned(), dedicated.bind.to_string()];
    names.extend(
        dedicated
            .public_url
            .as_ref()
            .and_then(|url| url.host_str())
            .map(|host| host.trim_matches(['[', ']']).to_owned()),
    );
    names.dedup();
    let generated = rcgen::generate_simple_self_signed(names)
        .map_err(|error| SelfSignedError::Generate(error.to_string()))?;
    private_dir(&dir).map_err(|error| write_failure(&error))?;
    write_atomic(
        &dir,
        KEY_FILE,
        generated.signing_key.serialize_pem().as_bytes(),
    )
    .map_err(|error| write_failure(&error))?;
    write_atomic(&dir, CERT_FILE, generated.cert.pem().as_bytes())
        .map_err(|error| write_failure(&error))?;
    Ok((cert, key))
}

/// A write failure.
fn write_failure(error: &dyn Display) -> SelfSignedError {
    SelfSignedError::Write(error.to_string())
}

#[cfg(all(test, unix))]
#[expect(
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use kcc_app::settings::mcp_schema::DedicatedListenerConfig;

    use super::ensure;

    /// Todo 26: the generated key is owner-only (0600) and a second start reuses the
    /// certificate instead of generating another one.
    #[test]
    fn the_key_is_owner_only_and_generated_once() -> Result<(), Box<dyn Error>> {
        let dir = tempfile::TempDir::new()?;
        let dedicated = DedicatedListenerConfig::default();

        let (cert, key) = ensure(dir.path(), &dedicated)?;
        let first = fs::read(&cert)?;
        let (again, _key) = ensure(dir.path(), &dedicated)?;

        assert_eq!(fs::metadata(&key)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(again)?, first);
        Ok(())
    }
}
