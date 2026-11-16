//! Removing credential files: absent paths are accepted, and legacy plaintext is
//! overwritten before it is unlinked.

use std::{
    fs::{self, Metadata, OpenOptions},
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
/// Only a regular file is overwritten. A symbolic link (or any other entry) is
/// removed as a directory entry: the file it names is neither written nor
/// removed.
///
/// # Errors
/// Returns a typed storage failure and leaves the path present when overwrite fails.
pub(super) fn secure_remove(path: &Path) -> Result<(), CredentialError> {
    let listed = fs::symlink_metadata(path)
        .map_err(|source| CredentialError::State(io_error(path, source)))?;
    if listed.is_file() {
        overwrite(path, &listed)?;
    }
    remove_if_present(path)
}

/// Overwrites the regular file `listed` at `path` with zeros and truncates it.
///
/// The open follows a link, so on unix a file swapped in after `listed` was read
/// is detected by its device and inode and refused before anything is written.
///
/// # Errors
/// Returns a typed storage failure.
fn overwrite(path: &Path, listed: &Metadata) -> Result<(), CredentialError> {
    let state = |source| CredentialError::State(io_error(path, source));
    let mut file = OpenOptions::new().write(true).open(path).map_err(state)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file.metadata().map_err(state)?;
        if (opened.dev(), opened.ino()) != (listed.dev(), listed.ino()) {
            return Err(state(io::ErrorKind::AlreadyExists.into()));
        }
    }
    let zeros = Zeroizing::new([0_u8; 8_192]);
    let chunk_len = u64::try_from(zeros.len()).map_err(|_error| CredentialError::Record)?;
    let mut remaining = listed.len();
    file.rewind().map_err(state)?;
    while remaining != 0 {
        let count =
            usize::try_from(remaining.min(chunk_len)).map_err(|_error| CredentialError::Record)?;
        let chunk = zeros.get(..count).ok_or(CredentialError::Record)?;
        file.write_all(chunk).map_err(state)?;
        remaining = remaining.saturating_sub(u64::try_from(count).unwrap_or(remaining));
    }
    file.set_len(0)
        .and_then(|()| file.sync_all())
        .map_err(state)
}
