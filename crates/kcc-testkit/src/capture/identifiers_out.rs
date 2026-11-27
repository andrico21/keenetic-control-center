//! The optional identifiers list: where it may be written and how it is appended.

use alloc::collections::BTreeSet;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{self, Path, PathBuf},
};

use crate::anonymize::{Identifier, IdentifierKind};

/// Whether `file` is refused as the identifiers list of a capture below `out`.
///
/// It is when it exists and is not a regular file with one link (a symlink, dangling or
/// not and never followed, a directory, FIFO, socket or hard link), or when it lies
/// anywhere under `out`.
///
/// Symlinks in the existing ancestors of either path are resolved. Call it again once the
/// capture directory exists: only then does a link to a new directory resolve.
///
/// # Errors
///
/// I/O errors from inspecting `file` or resolving an existing path.
#[inline]
pub fn refused(file: &Path, out: &Path) -> io::Result<bool> {
    Ok(!is_plain(file)? || resolved(file)?.starts_with(resolved(out)?))
}

/// Whether `file` is missing or a regular file with no other link, never following a
/// symlink.
///
/// # Errors
///
/// I/O errors other than a missing `file`.
fn is_plain(file: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(file) {
        Ok(metadata) => Ok(single(&metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether `metadata` is of a regular file with one link (on Unix; elsewhere a regular file).
fn single(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.is_file() && metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// `path` made absolute, its longest existing ancestor (or itself) resolved through symlinks.
///
/// # Errors
///
/// I/O errors from making the path absolute or resolving the existing ancestor.
fn resolved(path: &Path) -> io::Result<PathBuf> {
    let absolute = path::absolute(path)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name);
                existing = parent;
            }
            (None | Some(_), _) => return Ok(absolute.clone()),
        }
    }
    let mut resolved = fs::canonicalize(existing)?;
    resolved.extend(missing.into_iter().rev());
    Ok(resolved)
}

/// Appends to `file` every non-secret identifier it does not list yet, one per line,
/// creating it owner-readable only (mode 0600 on Unix).
///
/// Anything but a missing or regular file with one link is refused before it is opened (so
/// a FIFO cannot block), the opened file must be one too, and on Unix it must still be the
/// one named `file`, so nothing is written through a link swapped in meanwhile.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for a symlink, a file that is not regular, a hard link
/// or a file swapped while it was opened; I/O errors from reading or writing `file`.
#[inline]
pub fn append_identifiers(file: &Path, identifiers: &[Identifier]) -> io::Result<()> {
    if !is_plain(file)? {
        return Err(not_a_plain_file());
    }
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    let mut output = options.open(file)?;
    if !single(&output.metadata()?) {
        return Err(not_a_plain_file());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = output.metadata()?;
        let named = fs::symlink_metadata(file)?;
        if named.file_type().is_symlink()
            || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
        {
            return Err(not_a_plain_file());
        }
    }
    let mut existing = String::new();
    #[expect(
        clippy::verbose_file_reads,
        reason = "the list is read through the handle just opened and checked, never by path"
    )]
    let _: usize = output.read_to_string(&mut existing)?;
    let mut listed: BTreeSet<&str> = existing.lines().collect();
    let mut added = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        added.push('\n');
    }
    for identifier in identifiers {
        let value = identifier.value.as_str();
        if identifier.kind != IdentifierKind::Secret
            && !value.contains('\n')
            && listed.insert(value)
        {
            added.push_str(value);
            added.push('\n');
        }
    }
    output.write_all(added.as_bytes())
}

/// The error for an identifiers list that is not a regular file with one link, or was
/// swapped while opened.
fn not_a_plain_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the identifiers list must be a regular file with one link, not a symlink",
    )
}

#[cfg(test)]
mod tests {
    //! Symlinks as the identifiers list.

    use core::error::Error;

    /// A dangling file symlink into the capture is refused before the capture exists, and
    /// appending through any symlink fails without creating its target (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when a symlink is accepted or its target is created.
    #[cfg(unix)]
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn symlinks_are_refused_and_never_followed() -> Result<(), Box<dyn Error>> {
        use std::{fs, os::unix::fs::symlink};

        use tempfile::TempDir;

        use super::{append_identifiers, refused};
        use crate::anonymize::{Identifier, IdentifierKind};

        let scratch = TempDir::new()?;
        let out = scratch.path().join("out");
        let inside = out.join("capture").join("ids.txt");
        let link = scratch.path().join("fl.txt");
        symlink(&inside, &link)?;
        assert!(refused(&link, &out)?, "dangling file link accepted");
        let outside = scratch.path().join("plain.txt");
        assert!(!refused(&outside, &out)?, "plain file refused");
        fs::create_dir_all(inside.parent().ok_or("no parent")?)?;
        let listed = [Identifier {
            value: "host-value".to_owned(),
            kind: IdentifierKind::Host,
        }];
        assert!(append_identifiers(&link, &listed).is_err(), "link followed");
        assert!(fs::symlink_metadata(&inside).is_err(), "target created");
        Ok(())
    }

    /// Every path under the `--out` root is refused, also another capture's directory and a
    /// path through the real directory of a symlinked root; a plain file outside is not
    /// (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when a path under the root is accepted or one outside it is refused.
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn paths_under_the_out_root_are_refused() -> Result<(), Box<dyn Error>> {
        use std::fs;

        use tempfile::TempDir;

        use super::refused;

        let scratch = TempDir::new()?;
        let out = scratch.path().join("out");
        fs::create_dir_all(out.join("OTHER-1.0"))?;
        for (case, file) in [
            ("another capture", out.join("OTHER-1.0").join("ids.txt")),
            ("the root itself", out.join("ids.txt")),
            ("a missing capture", out.join("capture").join("ids.txt")),
        ] {
            assert!(refused(&file, &out)?, "{case} accepted");
        }
        assert!(
            !refused(&scratch.path().join("ids.txt"), &out)?,
            "a file outside the root refused"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = scratch.path().join("real");
            fs::create_dir_all(real.join("capture"))?;
            let link = scratch.path().join("link");
            symlink(&real, &link)?;
            assert!(
                refused(&real.join("capture").join("ids.txt"), &link)?,
                "a path through the real directory of a symlinked root accepted"
            );
        }
        Ok(())
    }

    /// A directory, a socket and a hard-linked file are refused as the identifiers list and
    /// never written (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when such a path is accepted or the linked file changes.
    #[cfg(unix)]
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn non_regular_files_and_hard_links_are_refused() -> Result<(), Box<dyn Error>> {
        use std::{fs, os::unix::net::UnixListener};

        use tempfile::TempDir;

        use super::{append_identifiers, refused};
        use crate::anonymize::{Identifier, IdentifierKind};

        let scratch = TempDir::new()?;
        let out = scratch.path().join("out");
        let directory = scratch.path().join("dir");
        fs::create_dir_all(&directory)?;
        let socket = scratch.path().join("sock");
        let _listener = UnixListener::bind(&socket)?;
        let original = scratch.path().join("original.txt");
        fs::write(&original, "kept\n")?;
        let linked = scratch.path().join("linked.txt");
        fs::hard_link(&original, &linked)?;
        let listed = [Identifier {
            value: "host-value".to_owned(),
            kind: IdentifierKind::Host,
        }];
        for (case, file) in [
            ("directory", &directory),
            ("socket", &socket),
            ("hard link", &linked),
        ] {
            assert!(refused(file, &out)?, "{case} accepted");
            assert!(append_identifiers(file, &listed).is_err(), "{case} written");
        }
        assert_eq!(
            fs::read_to_string(&original)?,
            "kept\n",
            "the linked file changed"
        );
        Ok(())
    }
}
