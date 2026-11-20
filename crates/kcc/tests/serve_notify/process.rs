//! The `kcc serve` child of the notification suite, and the files it leaves.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Child,
    sync::mpsc,
};

use tokio::task::block_in_place;

use crate::support::TestResult;

/// The running server; killed on drop.
pub(crate) struct Server {
    /// The `kcc serve` process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every stderr line read so far.
    seen: Vec<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// The server `child` whose stderr `lines` come in, with the lines `seen` so far.
    pub(crate) const fn new(
        child: Child,
        lines: mpsc::Receiver<String>,
        seen: Vec<String>,
    ) -> Self {
        Self { child, lines, seen }
    }

    /// Kills the server and returns everything it wrote to stderr.
    pub(crate) fn finish(mut self) -> String {
        drop(self.child.kill());
        drop(self.child.wait());
        block_in_place(|| {
            while let Ok(line) = self.lines.recv() {
                self.seen.push(line);
            }
        });
        self.seen.join("\n")
    }
}

/// Every file below `dir` with its bytes, lock files left out (Windows refuses to read
/// a locked one).
pub(crate) fn files(dir: &Path) -> TestResult<Vec<(PathBuf, Vec<u8>)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(files(&path)?);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "lock") {
            let bytes = fs::read(&path)?;
            found.push((path, bytes));
        }
    }
    Ok(found)
}
