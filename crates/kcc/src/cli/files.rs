//! Owner-only files for secrets and private output.

use std::{
    fs::{DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

use kcc_app::persist::private_file;

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

/// Writes `bytes` to `path` with owner-only permissions.
///
/// A new file when `fresh`, otherwise atomically replacing it through a randomly
/// named temporary file. Neither way follows or reuses a symbolic link or a
/// planted file.
///
/// # Errors
///
/// Returns create, write, sync or rename failures; an existing file when `fresh`;
/// `AlreadyExists` for a symbolic link at `path`.
pub(crate) fn write_private(path: &Path, bytes: &[u8], fresh: bool) -> io::Result<()> {
    if !fresh {
        return private_file::replace(path, bytes).map_err(io::Error::other);
    }
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    let mut handle = options.open(path)?;
    handle.write_all(bytes)?;
    handle.sync_all()
}

#[cfg(test)]
#[cfg(unix)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::{fs, os::unix::fs::symlink, path::Path};

    use tempfile::TempDir;

    use super::write_private;

    /// Names in `dir`, sorted.
    fn names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut found = fs::read_dir(dir)?
            .map(|entry| entry.map(|item| item.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        found.sort();
        Ok(found)
    }

    /// F-22, SEC2-17: a symlink planted at the old predictable temporary name
    /// (`<out>.kcc-tmp`) is never written through; the output lands in the
    /// directory as a new owner-only file.
    #[test]
    fn planted_temporary_symlink_is_not_followed() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let output = TempDir::new()?;
        let outside = TempDir::new()?;
        let victim = outside.path().join("victim");
        fs::write(&victim, "victim")?;
        symlink(&victim, output.path().join("plan.kcc-tmp"))?;
        let target = output.path().join("plan.json");

        write_private(&target, b"plan", false)?;

        assert_eq!(fs::read_to_string(&victim)?, "victim");
        assert_eq!(names(outside.path())?, ["victim"]);
        assert_eq!(fs::read_to_string(&target)?, "plan");
        let written = fs::symlink_metadata(&target)?;
        assert!(written.is_file());
        assert_eq!(written.permissions().mode() & 0o777, 0o600);
        assert_eq!(names(output.path())?, ["plan.json", "plan.kcc-tmp"]);
        Ok(())
    }

    /// SEC2-17: a symlink at the output path is refused, fresh or replacing;
    /// the link and the file it names stay as they were.
    #[test]
    fn symlink_at_the_output_path_is_refused() -> Result<(), Box<dyn Error>> {
        let output = TempDir::new()?;
        let outside = TempDir::new()?;
        let victim = outside.path().join("victim");
        fs::write(&victim, "victim")?;
        let target = output.path().join("report.html");
        symlink(&victim, &target)?;

        for fresh in [false, true] {
            assert!(write_private(&target, b"report", fresh).is_err(), "{fresh}");
        }

        assert_eq!(fs::read_to_string(&victim)?, "victim");
        assert_eq!(names(outside.path())?, ["victim"]);
        assert!(fs::symlink_metadata(&target)?.file_type().is_symlink());
        assert_eq!(names(output.path())?, ["report.html"]);
        Ok(())
    }
}
