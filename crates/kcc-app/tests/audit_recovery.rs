//! Audit appends that read only the chain tail, and recovery from a torn last line.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert on the audit files they create"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, fmt, ops::RangeInclusive, time::Duration};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use kcc_app::{
    accounts::Clock,
    audit::{
        AUDIT_FILE_NAME, Actor, ActorKind, AuditEntry, AuditError, AuditEvent, AuditLog,
        AuditPolicy, verify_chain,
    },
    persist::StateStore,
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

/// The repair clock's time, which names the quarantine file.
const NOW: u64 = 1_800_000_000;

struct FixedClock;

impl fmt::Debug for FixedClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedClock")
    }
}

impl Clock for FixedClock {
    fn unix_seconds(&self) -> u64 {
        NOW
    }
}

fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    Ok((temp, state))
}

fn policy() -> AuditPolicy {
    AuditPolicy::default().with_clock(Arc::new(FixedClock))
}

fn event(index: u64) -> AuditEvent {
    AuditEvent::new(
        1_700_000_000_u64.saturating_add(index),
        Actor::new(ActorKind::Cli, "recovery".to_owned()),
        "test.recovery".to_owned(),
    )
    .with_result("success".to_owned(), format!("recovery-{index}"))
}

async fn append_all(audit: &AuditLog, range: RangeInclusive<u64>) -> TestResult {
    for index in range {
        drop(audit.append(event(index)).await?);
    }
    Ok(())
}

fn active(state: &StateStore) -> PathBuf {
    state.dir().join(AUDIT_FILE_NAME)
}

/// Names of the quarantine files in the state directory.
fn quarantined(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for listed in fs::read_dir(dir)? {
        let name = listed?.file_name().to_string_lossy().into_owned();
        if name.starts_with("audit.jsonl.torn-") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Asserts that `entry` is the repair entry naming `file` and `bytes`.
fn assert_repair(entry: Option<&AuditEntry>, file: &str, bytes: usize) {
    let summary = entry.map(|found| {
        (
            found.action.as_str(),
            found.actor.kind,
            found.outcome.as_str(),
            found.params_redacted.clone(),
        )
    });
    assert_eq!(
        summary,
        Some((
            "audit.repair",
            ActorKind::System,
            "success",
            serde_json::json!({ "file": file, "bytes": bytes }),
        )),
        "the repair is audited with the quarantine name and size, never its content"
    );
}

/// `B-01` / `SEC2-05`: an append reads only the tail of the newest file, so an old
/// archive that cannot be read no longer stops it.
///
/// The chain stays linked, and full verification still reports the unreadable archive.
#[tokio::test]
async fn an_unreadable_old_archive_does_not_stop_appends() -> TestResult {
    let (_temp, state) = store()?;
    let rotating = AuditLog::spawn_with_policy(
        &state,
        policy().with_rotate_bytes(1).with_retention(Duration::ZERO),
    )?;
    append_all(&rotating, 1..=3).await?;
    drop(rotating);
    let audit = AuditLog::spawn_with_policy(&state, policy())?;
    let third = verify_chain(state.dir())?
        .pop()
        .ok_or("three entries were written")?;
    let oldest = state.dir().join(format!("audit-{:020}.jsonl", 1_u64));
    fs::remove_file(&oldest)?;
    fs::create_dir_all(&oldest)?;

    let fourth = audit.append(event(4)).await?;

    assert_eq!(
        (fourth.seq, fourth.prev_hash.as_str()),
        (4, third.hash.as_str()),
        "the append continues the chain from the newest file's tail"
    );
    assert!(
        verify_chain(state.dir()).is_err(),
        "full verification still reads every archive"
    );
    Ok(())
}

/// `B-03` / `SEC2-04`: a torn last line is moved aside when the writer starts.
///
/// The line is cut anywhere inside a real entry, as a crash or a full disk mid-append
/// leaves only a prefix of it. `audit.jsonl.torn-<unix-ts>` holds exactly the torn bytes.
/// A repair entry continues the chain from the last complete entry, the log verifies,
/// appends go on, and a later start finds nothing left to repair.
#[tokio::test]
async fn a_torn_last_line_is_quarantined_when_the_writer_starts() -> TestResult {
    let (_reference_temp, reference) = store()?;
    let writer = AuditLog::spawn_with_policy(&reference, policy())?;
    append_all(&writer, 1..=3).await?;
    drop(writer);
    let whole = fs::read(active(&reference))?;
    let body = whole
        .strip_suffix(b"\n")
        .ok_or("newline-terminated entries")?;
    let complete = body
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline.saturating_add(1));
    let last_line = body.len().saturating_sub(complete);
    let half = last_line.checked_div(2).unwrap_or(1);
    for cut in [1, 2, half, last_line.saturating_sub(1), last_line] {
        let (_temp, state) = store()?;
        let torn_end = complete.saturating_add(cut);
        let kept = whole.get(..torn_end).ok_or("cut inside the file")?;
        let torn = whole.get(complete..torn_end).ok_or("cut inside the file")?;
        fs::write(active(&state), kept)?;

        let audit = AuditLog::spawn_with_policy(&state, policy())?;

        let name = format!("audit.jsonl.torn-{NOW}");
        assert_eq!(quarantined(state.dir())?, vec![name.clone()], "cut {cut}");
        let moved = state.dir().join(&name);
        assert_eq!(fs::read(&moved)?, torn, "cut {cut}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&moved)?.permissions().mode() & 0o777, 0o600);
        }
        let entries = verify_chain(state.dir())?;
        assert_eq!(
            entries.len(),
            3,
            "cut {cut}: two complete entries and the repair"
        );
        assert_repair(entries.last(), &name, cut);
        assert_eq!(audit.append(event(4)).await?.seq, 4, "cut {cut}");
        drop(audit);
        let restarted = AuditLog::spawn_with_policy(&state, policy())?;
        assert_eq!(restarted.append(event(5)).await?.seq, 5, "cut {cut}");
        assert_eq!(
            quarantined(state.dir())?.len(),
            1,
            "cut {cut}: repaired once"
        );
        assert_eq!(verify_chain(state.dir())?.len(), 5, "cut {cut}");
    }
    Ok(())
}

/// `SEC2-04`: a torn line left by another process that crashed mid-append is moved aside
/// before this writer's next append, which then follows the repair entry.
#[tokio::test]
async fn a_torn_last_line_is_quarantined_before_the_next_append() -> TestResult {
    let (_temp, state) = store()?;
    let audit = AuditLog::spawn_with_policy(&state, policy())?;
    append_all(&audit, 1..=2).await?;
    let fragment = br#"{"ts":1700000003,"seq":3,"actor":{"kind":"cli","id":"rec"#;
    OpenOptions::new()
        .append(true)
        .open(active(&state))?
        .write_all(fragment)?;

    let written = audit.append(event(3)).await?;

    let name = format!("audit.jsonl.torn-{NOW}");
    assert_eq!(fs::read(state.dir().join(&name))?, fragment);
    assert_eq!(written.seq, 4, "the repair entry took sequence 3");
    let entries = verify_chain(state.dir())?;
    assert_repair(entries.get(2), &name, fragment.len());
    assert_eq!(entries.len(), 4);
    Ok(())
}

/// `B-03`: only an incomplete last line is crash damage. A complete last line that does
/// not verify is tampering: the writer refuses to start, nothing is moved and the file
/// is left as it was.
#[tokio::test]
async fn a_complete_bad_last_line_is_refused_not_repaired() -> TestResult {
    let (_reference_temp, reference) = store()?;
    let writer = AuditLog::spawn_with_policy(&reference, policy())?;
    append_all(&writer, 1..=2).await?;
    drop(writer);
    let whole = String::from_utf8(fs::read(active(&reference))?)?;
    let forged = whole.replacen("recovery-2", "recovery-X", 1);
    for (case, content) in [
        ("forged hash", forged),
        ("not an entry", format!("{whole}not an entry\n")),
    ] {
        let (_temp, state) = store()?;
        fs::write(active(&state), &content)?;

        let started = AuditLog::spawn_with_policy(&state, policy());

        assert!(
            matches!(
                started,
                Err(AuditError::Chain { seq: 2 } | AuditError::Json { reason: _ })
            ),
            "{case}: {started:?}"
        );
        assert_eq!(quarantined(state.dir())?, Vec::<String>::new(), "{case}");
        assert_eq!(fs::read_to_string(active(&state))?, content, "{case}");
    }
    Ok(())
}

/// `B-03`: a complete last line that is not an entry, written while the writer runs, is
/// refused by the next append and left in place.
#[tokio::test]
async fn a_complete_bad_last_line_stops_the_next_append() -> TestResult {
    let (_temp, state) = store()?;
    let audit = AuditLog::spawn_with_policy(&state, policy())?;
    append_all(&audit, 1..=1).await?;
    OpenOptions::new()
        .append(true)
        .open(active(&state))?
        .write_all(b"not an entry\n")?;
    let before = fs::read(active(&state))?;

    let refused = audit.append(event(2)).await;

    assert!(refused.is_err(), "{refused:?}");
    assert!(!audit.is_alive(), "a bad complete line ends the writer");
    assert_eq!(quarantined(state.dir())?, Vec::<String>::new());
    assert_eq!(
        fs::read(active(&state))?,
        before,
        "the line is never truncated"
    );
    Ok(())
}
