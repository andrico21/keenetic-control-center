//! Removing credential files: absent paths are accepted, and legacy plaintext is
//! overwritten before it is unlinked.

use std::{
    fs::{self, OpenOptions},
    io::{self, Seek as _, Write as _},
    path::Path,
};

use zeroize::Zeroizing;

use super::CredentialError;
use crate::persist::io_error;

/// Removes a credential path, accepting an already absent path.
///
/// # Errors
/// Returns a typed storage failure.
pub(super) fn remove_if_present(path: &Path) -> Result<(), CredentialError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CredentialError::State(io_error(path, source))),
    }
}

/// Overwrites a legacy plaintext file before removing it.
///
/// # Errors
/// Returns a typed storage failure and leaves the path present when overwrite fails.
pub(super) fn secure_remove(path: &Path) -> Result<(), CredentialError> {
    let length = fs::metadata(path)
        .map_err(|source| CredentialError::State(io_error(path, source)))?
        .len();
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|source| CredentialError::State(io_error(path, source)))?;
    let zeros = Zeroizing::new([0_u8; 8_192]);
    let chunk_len = u64::try_from(zeros.len()).map_err(|_error| CredentialError::Record)?;
    let mut remaining = length;
    file.rewind()
        .map_err(|source| CredentialError::State(io_error(path, source)))?;
    while remaining != 0 {
        let count =
            usize::try_from(remaining.min(chunk_len)).map_err(|_error| CredentialError::Record)?;
        let chunk = zeros.get(..count).ok_or(CredentialError::Record)?;
        file.write_all(chunk)
            .map_err(|source| CredentialError::State(io_error(path, source)))?;
        remaining = remaining.saturating_sub(u64::try_from(count).unwrap_or(remaining));
    }
    file.set_len(0)
        .and_then(|()| file.sync_all())
        .map_err(|source| CredentialError::State(io_error(path, source)))?;
    drop(file);
    remove_if_present(path)
}
