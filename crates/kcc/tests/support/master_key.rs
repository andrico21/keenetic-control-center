//! The master key file every `kcc` child process reads.

use std::{fs, io, path::Path};

/// Writes `key` to `path`, readable by its owner only, as kcc requires of a key file.
pub(crate) fn write(path: &Path, key: [u8; 32]) -> io::Result<()> {
    fs::write(path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
