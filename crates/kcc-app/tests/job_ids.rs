//! Job identifiers cannot be guessed from other jobs.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert the identifiers of started jobs"
)]

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};
use core::{error::Error, fmt, time::Duration};

use kcc_app::{
    accounts::Clock, audit::AuditLog, jobs::JobRunner, persist::StateStore,
    registry::RouterRegistry, settings::OutboundConfig,
};
use tempfile::TempDir;

/// A clock that never moves.
struct Frozen;

impl fmt::Debug for Frozen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Frozen")
    }
}

impl Clock for Frozen {
    fn unix_seconds(&self) -> u64 {
        1_800_000_000
    }
}

/// W4-02: job ids carry 128 random bits and nothing derived from the clock, the process
/// or a counter.
///
/// Jobs started one after another in the same second get distinct ids of the form
/// `job-<32 lowercase hex digits>`, and the ids are not in the order the jobs started,
/// so one's own job reveals nothing about the ids of the others.
#[tokio::test]
async fn job_ids_are_random_not_sequential() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let runner = JobRunner::open_with_retention(
        state.clone(),
        registry,
        AuditLog::spawn(&state)?,
        Duration::from_secs(100),
        Arc::new(Frozen),
    )
    .await?;
    let mut ids = Vec::new();
    for _ in 0_u8..64 {
        ids.push(
            runner
                .start("probe".to_owned(), None, false, async |_context| Ok(()))
                .await?,
        );
    }
    for id in &ids {
        let digits = id.strip_prefix("job-").ok_or("no job- prefix")?;
        assert!(
            digits.len() == 32
                && digits
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "not 128 bits of lowercase hex: {id}"
        );
    }
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "{ids:?}"
    );
    assert!(!ids.is_sorted(), "ids in start order: {ids:?}");
    Ok(())
}
