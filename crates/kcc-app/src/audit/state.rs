//! The writer's state and its append path, run while the append lock is held.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    fs::{self, File},
    io::Write as _,
    path::PathBuf,
};

use super::{
    AUDIT_FILE_NAME, AuditEntry, AuditError, AuditEvent, AuditPolicy, append_lock::RetryPolicy,
    chain, json_error, repair, tail,
};
use crate::{
    accounts::Clock,
    persist::{StateLock, StateStore, io_error, open_private_append_file},
};

/// What the writer task owns. Nothing about the chain is cached: every append reads it
/// from the files under the lock, so the appends of every process form one chain.
#[derive(Debug)]
pub(super) struct WriterState {
    /// State store used to coordinate appenders in other processes.
    store: StateStore,
    /// Audit directory.
    dir: PathBuf,
    /// Rotation threshold.
    rotate_bytes: u64,
    /// Maximum age of complete rotated files.
    retention: Duration,
    /// Time source for retention and repairs.
    clock: Arc<dyn Clock>,
    /// Bounded cross-process append-lock retry policy.
    append_lock_retry: RetryPolicy,
}

impl WriterState {
    /// The state of a writer for `store` under `policy`.
    pub(super) fn new(store: StateStore, policy: AuditPolicy) -> Self {
        Self {
            dir: store.dir().to_owned(),
            store,
            rotate_bytes: policy.rotate_bytes,
            retention: policy.retention,
            clock: policy.clock,
            append_lock_retry: policy.append_lock_retry,
        }
    }

    /// The state store whose lock serializes appenders.
    pub(super) const fn store(&self) -> &StateStore {
        &self.store
    }

    /// The bounded retry policy of the append lock.
    pub(super) const fn append_lock_retry(&self) -> RetryPolicy {
        self.append_lock_retry
    }

    /// Repairs a torn last line, then appends `event`; returns the repair entry, if one
    /// was written, and the event's entry, in chain order.
    ///
    /// # Errors
    ///
    /// Returns serialization, I/O, chain or rotation errors.
    pub(super) fn append_locked(
        &self,
        event: AuditEvent,
        lock: &StateLock,
    ) -> Result<(Option<AuditEntry>, AuditEntry), AuditError> {
        let repaired = self.repair(lock)?;
        Ok((repaired, self.write(event, lock)?))
    }

    /// Moves a torn last line of the active file aside, logs it and records the repair;
    /// returns the repair entry when there was one.
    ///
    /// # Errors
    ///
    /// Returns I/O, serialization or chain errors.
    pub(super) fn repair(&self, lock: &StateLock) -> Result<Option<AuditEntry>, AuditError> {
        let mut active = open_private_append_file(&self.dir.join(AUDIT_FILE_NAME))?;
        let now = self.clock.unix_seconds();
        let Some(torn) = repair::quarantine(&self.dir, &mut active, now)? else {
            return Ok(None);
        };
        tracing::warn!(
            file = torn.name(),
            bytes = torn.bytes(),
            "the audit log ended in an incomplete line; it was moved aside and the repair recorded"
        );
        self.write(torn.event(now), lock).map(Some)
    }

    /// Chains `event` to the tail of the newest file, rotates if needed, appends and syncs.
    ///
    /// # Errors
    ///
    /// Returns serialization, I/O, chain or rotation errors.
    fn write(&self, event: AuditEvent, _lock: &StateLock) -> Result<AuditEntry, AuditError> {
        let path = self.dir.join(AUDIT_FILE_NAME);
        let mut file = open_private_append_file(&path)?;
        let (seq, prev_hash) = tail::chain_head(&self.dir, &mut file, &path)?;
        let mut entry = AuditEntry {
            ts: event.ts,
            seq,
            actor: event.actor,
            router: event.router,
            action: event.action,
            target: event.target,
            params_redacted: event.params_redacted,
            outcome: event.outcome,
            request_id: event.request_id,
            prev_hash,
            hash: String::new(),
        };
        entry.hash = chain::calculate_hash(&entry)?;
        let mut bytes = serde_json::to_vec(&entry).map_err(|error| json_error(&error))?;
        bytes.push(b'\n');
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let size = file
            .metadata()
            .map_err(|error| io_error(&path, error))?
            .len();
        if size > 0 && size.saturating_add(byte_count) > self.rotate_bytes {
            file = self.rotate(&file, seq)?;
            self.prune_rotated()?;
        }
        file.write_all(&bytes)
            .and_then(|()| file.sync_data())
            .map_err(|error| io_error(&path, error))?;
        Ok(entry)
    }

    /// Renames the active file to the archive named by the last sequence it holds and
    /// opens a new owner-only active file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if syncing, renaming, or reopening fails.
    fn rotate(&self, file: &File, next_seq: u64) -> Result<File, AuditError> {
        let active = self.dir.join(AUDIT_FILE_NAME);
        let archive = self
            .dir
            .join(format!("audit-{:020}.jsonl", next_seq.saturating_sub(1)));
        file.sync_all().map_err(|error| io_error(&active, error))?;
        fs::rename(&active, &archive).map_err(|error| io_error(&archive, error))?;
        Ok(open_private_append_file(&active)?)
    }

    /// Removes the oldest run of rotated files whose newest entry predates the cutoff.
    ///
    /// # Errors
    ///
    /// Returns an I/O or JSON error while inspecting or removing an archive.
    fn prune_rotated(&self) -> Result<(), AuditError> {
        let retention = self.retention.as_secs();
        if retention == 0 {
            return Ok(());
        }
        let cutoff = self.clock.unix_seconds().saturating_sub(retention);
        for path in chain::rotated_files(&self.dir)? {
            let mut archive = File::open(&path).map_err(|error| io_error(&path, error))?;
            let last = tail::last_entry(&mut archive, &path)?;
            drop(archive);
            if last.is_none_or(|entry| entry.ts >= cutoff) {
                break;
            }
            fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
        }
        Ok(())
    }
}
