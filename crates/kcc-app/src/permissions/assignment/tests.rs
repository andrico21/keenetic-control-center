//! A role deletion racing a role assignment.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

extern crate alloc;

use alloc::rc::Rc;
use core::{error::Error, time::Duration};
use std::{
    sync::mpsc::{self, Receiver},
    thread,
};

use tempfile::TempDir;

use super::{
    GrantError, holder_counts,
    probe::{self, Step},
    remove_unheld,
};
use crate::{
    api_keys::{ApiKeyError, create_api_key},
    permissions::{Permission, Role, RolesDocument, load_roles},
    persist::StateStore,
};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Longest wait for something that must happen.
const WAIT: Duration = Duration::from_secs(30);

/// What the assigning thread reports.
#[derive(Debug)]
enum Assigner {
    /// It is about to wait for the roles lock.
    Locking,
    /// It finished; `Ok` when the key was stored.
    Done(Result<(), ApiKeyError>),
}

/// Runs `work` on its own thread and hands back its result.
fn on_thread<T, F>(work: F) -> Receiver<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    drop(thread::spawn(move || sender.send(work())));
    receiver
}

/// W1-17: an assignment cannot slip between a role deletion's count and its removal.
///
/// A role deletion holds the roles, users and API-key locks from its holder count to its
/// removal, and an assignment holds the roles lock from its role check to its write, so
/// an assignment that starts in between cannot leave a holder of the deleted role.
///
/// The deletion is held right after counting no holders. The assignment then runs until
/// it either finishes or is about to wait for the roles lock; only then may the deletion
/// go on.
#[test]
fn an_assignment_cannot_slip_into_a_role_deletion() -> TestResult {
    let temp = TempDir::new()?;
    let store = StateStore::open(&temp.path().join("state"))?;
    let lab = Role::new(
        "lab-ops".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    );
    store.write(&RolesDocument { roles: vec![lab] })?;

    let (counted, deletion_counted) = mpsc::channel();
    let (go, deletion_go) = mpsc::channel::<()>();
    let deleting = store.clone();
    let deletion = on_thread(move || {
        probe::install(Rc::new(move |step| {
            if step == Step::Counted && counted.send(()).is_ok() {
                deletion_go.recv_timeout(WAIT).unwrap_or_default();
            }
        }));
        deleting.update(|roles: &mut RolesDocument| remove_unheld(&deleting, roles, "lab-ops"))?
    });
    deletion_counted.recv_timeout(WAIT)?;

    let (report, reports) = mpsc::channel();
    let assigning = store.clone();
    drop(thread::spawn(move || {
        let locking = report.clone();
        probe::install(Rc::new(move |step| {
            if step == Step::Locking {
                drop(locking.send(Assigner::Locking));
            }
        }));
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        let created = create_api_key(
            &assigning,
            &admin,
            "ci".to_owned(),
            "lab-ops".to_owned(),
            1,
            None,
        );
        drop(report.send(Assigner::Done(created.map(drop))));
    }));
    let first = reports.recv_timeout(WAIT)?;
    go.send(())?;

    let removed = deletion.recv_timeout(WAIT)??;
    let granted = match first {
        Assigner::Done(result) => result,
        Assigner::Locking => match reports.recv_timeout(WAIT)? {
            Assigner::Done(result) => result,
            Assigner::Locking => return Err("the assignment reported locking twice".into()),
        },
    };
    let held = holder_counts(&store)?.get("lab-ops").copied().unwrap_or(0);
    let exists = load_roles(&store)?
        .iter()
        .any(|role| role.name == "lab-ops");
    assert!(
        exists || held == 0,
        "deleted role still held: removed={removed}, granted={granted:?}"
    );
    assert!(removed, "nobody held the role when it was counted");
    assert!(
        matches!(
            granted,
            Err(ApiKeyError::Grant(GrantError::UnknownRole { name: _ }))
        ),
        "the assignment after the deletion: {granted:?}"
    );
    Ok(())
}
