//! Password files of routers added in the Web UI.
//!
//! The registry reads router passwords from files, so a password typed into the router
//! form is written to `<credentials dir>/<router>.password`: on unix the directory is
//! `0700` and the file `0600`, written to a temporary name, synced and renamed into place.
//! The secret never enters a log, an error message or the audit log.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use secrecy::{ExposeSecret as _, SecretString};
use tokio::task::spawn_blocking;

/// The password file kcc manages for `router` in `dir`.
pub(crate) fn path(dir: &Path, router: &str) -> PathBuf {
    dir.join(format!("{router}.password"))
}

/// Writes `password` to `file` (inside `dir`) with owner-only permissions.
///
/// # Errors
///
/// Returns directory, file or rename failures and a failed blocking task.
// NOT cancel-safe: the blocking write continues after cancellation and may still replace
// the file.
pub(crate) async fn store(dir: PathBuf, file: PathBuf, password: SecretString) -> io::Result<()> {
    spawn_blocking(move || write(&dir, &file, &password))
        .await
        .map_err(io::Error::other)?
}

/// Deletes `file`; a file that does not exist counts as deleted.
///
/// # Errors
///
/// Returns removal failures other than a missing file and a failed blocking task.
// NOT cancel-safe: the blocking removal continues after cancellation.
pub(crate) async fn remove(file: PathBuf) -> io::Result<()> {
    spawn_blocking(move || match fs::remove_file(&file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    })
    .await
    .map_err(io::Error::other)?
}

/// Creates `dir` if needed, then replaces `file` with `password` atomically.
///
/// # Errors
///
/// Returns directory, file, sync or rename failures.
fn write(dir: &Path, file: &Path, password: &SecretString) -> io::Result<()> {
    let mut directory = DirBuilder::new();
    let _: &mut DirBuilder = directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let _: &mut DirBuilder = directory.mode(0o700);
    }
    directory.create(dir)?;
    let temporary = file.with_extension("password.tmp");
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    let mut handle = options.open(&temporary)?;
    handle.write_all(password.expose_secret().as_bytes())?;
    handle.sync_all()?;
    drop(handle);
    fs::rename(&temporary, file)
}
