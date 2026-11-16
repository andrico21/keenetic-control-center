//! The wizards' sessions: one turn per run, whatever other runs come and go.
#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
use alloc::sync::Arc;

use super::Wizards;
use crate::migrate_wizard::record::Record;

/// The id of the `index`th run.
fn id(index: u32) -> String {
    format!("1700000000-{index:016x}")
}

/// W5-12: a session whose turn a request holds is not forgotten when 64 other runs
/// open, so the next request on that run waits for the same turn.
#[tokio::test]
async fn a_session_whose_turn_is_held_is_kept() {
    let wizards = Wizards::<Record>::default();
    let held = wizards.session(&id(0)).turn().await;
    for index in 1..=64 {
        drop(wizards.session(&id(index)));
    }
    assert!(
        wizards.session(&id(0)).turn.try_lock().is_err(),
        "the run's turn is still the held one"
    );
    drop(held);
}

/// W2-02: a session another request still uses is not forgotten when 64 other runs
/// open.
#[test]
fn a_session_in_use_is_kept() {
    let wizards = Wizards::<Record>::default();
    let used = wizards.session(&id(0));
    for index in 1..=64 {
        drop(wizards.session(&id(index)));
    }
    assert!(Arc::ptr_eq(&used, &wizards.session(&id(0))), "same session");
}
