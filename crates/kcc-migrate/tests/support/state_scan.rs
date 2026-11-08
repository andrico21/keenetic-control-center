//! Byte scan of every file below a state directory.

use std::{fs, io, path::Path};

/// One needle found in one file: the needle's label and the file path.
pub(crate) type Hit = (String, String);

/// Every regular file below `root`, recursively, as paths relative to `root`.
///
/// # Errors
/// Returns directory or metadata read failures.
pub(crate) fn files(root: &Path) -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Every `(label, file)` pair whose file bytes contain the labelled needle.
///
/// # Errors
/// Returns file read failures.
pub(crate) fn hits(root: &Path, needles: &[(&str, &[u8])]) -> io::Result<Vec<Hit>> {
    let mut found = Vec::new();
    for file in files(root)? {
        let bytes = fs::read(root.join(&file))?;
        for &(label, needle) in needles {
            if bytes.windows(needle.len()).any(|window| window == needle) {
                found.push((label.to_owned(), file.clone()));
            }
        }
    }
    Ok(found)
}
