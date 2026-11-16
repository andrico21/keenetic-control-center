//! Replacing an owner-only file in a directory kcc does not own.

use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::Path,
};

use chacha20poly1305::aead::Generate as _;

use super::{StateError, io_error, publish, sync_dir};

/// Atomically replaces `path` with `bytes` as an owner-only file.
///
/// The temporary file gets a random name in `path`'s directory and is created
/// exclusively, so a planted file or symbolic link is never reused or written
/// through. A symbolic link at `path` is refused; the final rename replaces a
/// directory entry and never follows one.
///
/// # Errors
///
/// [`StateError::Io`]: `AlreadyExists` when `path` is a symbolic link, or a
/// create, write, sync or rename failure.
#[inline]
pub fn replace(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let name = path
        .file_name()
        .ok_or_else(|| io_error(path, io::ErrorKind::InvalidInput.into()))?;
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_symlink() => {
            return Err(io_error(path, io::ErrorKind::AlreadyExists.into()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(path, error)),
    }
    let temp = dir.join(temporary_name(name).map_err(|error| io_error(path, error))?);
    publish(&temp, path, bytes)?;
    sync_dir(dir)
}

/// A fresh hidden temporary name for `name`: `.<name>.<16 random hex>.kcc-tmp`.
///
/// # Errors
///
/// An I/O error when the OS random source fails.
fn temporary_name(name: &OsStr) -> io::Result<OsString> {
    let random = <[u8; 8]>::try_generate().map_err(|error| io::Error::other(error.to_string()))?;
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".{:016x}.kcc-tmp", u64::from_le_bytes(random)));
    Ok(temporary)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::temporary_name;

    /// F-22: the temporary name is random per call, hidden, and a single
    /// component, so it stays in the target's directory.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertions are the test contract"
    )]
    fn temporary_names_are_random_per_call() -> io::Result<()> {
        let first = temporary_name("plan.json".as_ref())?;
        let second = temporary_name("plan.json".as_ref())?;
        assert_ne!(first, second);
        for name in [&first, &second] {
            let text = name.to_string_lossy();
            assert!(
                text.starts_with(".plan.json.") && text.ends_with(".kcc-tmp"),
                "{text}"
            );
            assert!(!text.contains('/'), "{text}");
        }
        Ok(())
    }
}
