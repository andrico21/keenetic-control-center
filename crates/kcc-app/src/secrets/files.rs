//! Operator secret files: refused on Unix when group or others can read them.
//!
//! The rule is the master key's: a file whose mode grants any group or other
//! permission is refused before a byte is read. Windows has no mode check.

use std::{
    fs::{File, Metadata},
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use secrecy::SecretString;
use tokio::{fs::File as AsyncFile, io::AsyncReadExt as _};
use zeroize::Zeroizing;

/// Error opening or reading an operator secret file. Never carries its contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretFileError {
    /// The file cannot be opened or read.
    #[error("cannot read secret file {path}: {source}")]
    Read {
        /// Secret file path.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Group or others have access to the file (unix only).
    #[error("{path} can be read by other users (chmod 600)")]
    Permissions {
        /// Secret file path.
        path: PathBuf,
    },
}

/// Opens a secret file after checking that only its owner can access it.
///
/// # Errors
///
/// [`SecretFileError::Read`], or (unix) [`SecretFileError::Permissions`].
#[inline]
pub fn open_secret_file(path: &Path) -> Result<File, SecretFileError> {
    let read = |source| SecretFileError::Read {
        path: path.to_owned(),
        source,
    };
    let file = File::open(path).map_err(read)?;
    owner_only(&file.metadata().map_err(read)?, path)?;
    Ok(file)
}

/// Reads a secret file into wiped memory, dropping its trailing line break.
///
/// # Errors
///
/// As [`open_secret_file`], plus read failures.
#[inline]
pub fn read_secret_file(path: &Path) -> Result<SecretString, SecretFileError> {
    let mut text = Zeroizing::new(String::new());
    let _: usize = open_secret_file(path)?
        .read_to_string(&mut text)
        .map_err(|source| SecretFileError::Read {
            path: path.to_owned(),
            source,
        })?;
    Ok(trimmed(&text))
}

/// Reads a secret file without blocking the runtime, as [`read_secret_file`].
///
/// # Errors
///
/// As [`read_secret_file`].
// cancel-safe: the read does not mutate application state.
#[inline]
pub async fn read_secret_file_async(path: &Path) -> Result<SecretString, SecretFileError> {
    let read = |source| SecretFileError::Read {
        path: path.to_owned(),
        source,
    };
    let mut file = AsyncFile::open(path).await.map_err(read)?;
    owner_only(&file.metadata().await.map_err(read)?, path)?;
    let mut text = Zeroizing::new(String::new());
    let _: usize = file.read_to_string(&mut text).await.map_err(read)?;
    Ok(trimmed(&text))
}

/// Refuses `metadata` whose mode grants group or others any access (unix only).
///
/// # Errors
///
/// [`SecretFileError::Permissions`].
pub(crate) fn owner_only(metadata: &Metadata, path: &Path) -> Result<(), SecretFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SecretFileError::Permissions {
                path: path.to_owned(),
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _: (&Metadata, &Path) = (metadata, path);
    }
    Ok(())
}

/// The secret without its trailing CR/LF.
fn trimmed(text: &str) -> SecretString {
    SecretString::from(text.trim_end_matches(['\r', '\n']).to_owned())
}
