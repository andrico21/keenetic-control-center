//! Moving a torn last line of the active audit file aside.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

use serde_json::json;

use super::{
    AUDIT_FILE_NAME, Actor, ActorKind, AuditError, AuditEvent,
    tail::{read_range, torn_start},
};
use crate::persist::{StateError, create_private_file, io_error, sync_dir};

/// The action of the entry that records a repair.
const REPAIR_ACTION: &str = "audit.repair";
/// How many quarantine names one second offers before the repair gives up.
const NAME_ATTEMPTS: u32 = 64;

/// A torn last line, moved to a quarantine file.
#[derive(Debug)]
pub(super) struct Torn {
    /// File name of the quarantine file, in the audit directory.
    name: String,
    /// Number of bytes moved.
    bytes: u64,
}

impl Torn {
    /// The quarantine file name.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// The number of bytes moved.
    pub(super) const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The entry recording the repair at `now`: it names the quarantine file and its
    /// size, never its content.
    pub(super) fn event(&self, now: u64) -> AuditEvent {
        AuditEvent::new(
            now,
            Actor::new(ActorKind::System, "system".to_owned()),
            REPAIR_ACTION.to_owned(),
        )
        .with_params(json!({ "file": self.name, "bytes": self.bytes }))
        .with_result("success".to_owned(), format!("audit-repair-{now}"))
    }
}

/// Moves a torn last line of the active file to `audit.jsonl.torn-<now>`.
///
/// The bytes after the last `\n` of `active` (a line a crash or a full disk cut short)
/// go to a new owner-only file, then the active file is truncated back to that `\n`.
/// The caller holds the append lock. The fragment is durable in its own file before the
/// active file shrinks, so a crash in between at worst moves it twice; it is never lost.
///
/// # Errors
///
/// Returns an I/O error; nothing is truncated unless the copy is durable.
pub(super) fn quarantine(
    dir: &Path,
    active: &mut File,
    now: u64,
) -> Result<Option<Torn>, AuditError> {
    let path = dir.join(AUDIT_FILE_NAME);
    let len = active
        .metadata()
        .map_err(|error| io_error(&path, error))?
        .len();
    let Some(start) = torn_start(active, len).map_err(|error| io_error(&path, error))? else {
        return Ok(None);
    };
    let fragment = read_range(active, start, len).map_err(|error| io_error(&path, error))?;
    let (name, mut copy) = create_quarantine(dir, now)?;
    let copied = dir.join(&name);
    copy.write_all(&fragment)
        .and_then(|()| copy.sync_all())
        .map_err(|error| io_error(&copied, error))?;
    sync_dir(dir)?;
    OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|truncated| {
            truncated.set_len(start)?;
            truncated.sync_all()
        })
        .map_err(|error| io_error(&path, error))?;
    Ok(Some(Torn {
        name,
        bytes: len.saturating_sub(start),
    }))
}

/// Creates the quarantine file for `now`, adding `-2`, `-3`... when the name is taken.
///
/// # Errors
///
/// Returns the I/O error of the creation, or of the last name tried.
fn create_quarantine(dir: &Path, now: u64) -> Result<(String, File), AuditError> {
    let mut name = format!("{AUDIT_FILE_NAME}.torn-{now}");
    for attempt in 2..=NAME_ATTEMPTS {
        match create_private_file(&dir.join(&name)) {
            Ok(file) => return Ok((name, file)),
            Err(StateError::Io { source, path: _ })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                name = format!("{AUDIT_FILE_NAME}.torn-{now}-{attempt}");
            }
            Err(error) => return Err(error.into()),
        }
    }
    let file = create_private_file(&dir.join(&name))?;
    Ok((name, file))
}
