//! Owner-only files for secrets and private output.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

/// Creates `dir` (owner-only on unix) and its parents.
///
/// # Errors
///
/// Returns directory creation failures.
pub(crate) fn private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    let _: &mut DirBuilder = builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let _: &mut DirBuilder = builder.mode(0o700);
    }
    builder.create(dir)
}

/// Writes `bytes` to `path` with owner-only permissions: a new file when `fresh`,
/// otherwise atomically replacing it through a synced temporary file.
///
/// # Errors
///
/// Returns create, write, sync or rename failures; an existing file when `fresh`.
pub(crate) fn write_private(path: &Path, bytes: &[u8], fresh: bool) -> io::Result<()> {
    let temporary = path.with_extension("kcc-tmp");
    let target = if fresh { path } else { temporary.as_path() };
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true);
    if fresh {
        let _: &mut OpenOptions = options.create_new(true);
    } else {
        let _: &mut OpenOptions = options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    let mut handle = options.open(target)?;
    handle.write_all(bytes)?;
    handle.sync_all()?;
    drop(handle);
    if fresh {
        Ok(())
    } else {
        fs::rename(&temporary, path)
    }
}
