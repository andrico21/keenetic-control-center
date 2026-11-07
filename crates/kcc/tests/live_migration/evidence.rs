//! Append-only, value-free evidence lines for the live rehearsal.

use core::error::Error;
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::PathBuf,
};

use serde_json::Value;

/// Evidence file `.omo/evidence/task-31-live-migration.log` in the workspace.
pub(crate) struct Evidence {
    /// Open append handle.
    file: File,
}

impl Evidence {
    /// Opens the workspace evidence file for appending.
    ///
    /// # Errors
    /// Returns directory or file I/O failures.
    pub(crate) fn open() -> Result<Self, Box<dyn Error>> {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.omo/evidence");
        fs::create_dir_all(&directory)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join("task-31-live-migration.log"))?;
        Ok(Self { file })
    }

    /// Appends one JSON line and mirrors it to tracing; callers pass labels and counts only.
    ///
    /// # Errors
    /// Returns file I/O failures.
    pub(crate) fn record(&mut self, line: &Value) -> Result<(), Box<dyn Error>> {
        tracing::info!(evidence = %line, "live-migration");
        writeln!(self.file, "{line}")?;
        Ok(())
    }
}
