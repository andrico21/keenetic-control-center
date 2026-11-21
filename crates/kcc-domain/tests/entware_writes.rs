//! Entware write planners, drive initialize and the Entware drive guard, against the fake
//! router.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

#[path = "entware_writes/apply.rs"]
mod apply;
#[path = "entware_writes/drive.rs"]
mod drive;
#[path = "entware_writes/rules.rs"]
mod rules;
mod support;

use kcc_app::{
    permissions::{Permission, Role},
    workflow::WorkflowError,
};
use kcc_domain::{
    ChangeOp, Result as DomainResult, RouterCtx,
    entware::{self, models::EntwarePlan},
};

use crate::support::{Fixture, TestResult};

/// A role with every permission but `Destructive`.
fn operator() -> Role {
    Role::new(
        "operator".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != Permission::Destructive),
        vec!["*".to_owned()],
    )
}

/// A role that may only read.
fn viewer() -> Role {
    Role::new(
        "viewer".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    )
}

/// Applies `operation` through the protected workflow; `Ok(unsaved)` when it was read back.
async fn apply(fixture: &Fixture, operation: &ChangeOp) -> TestResult<Result<bool, WorkflowError>> {
    let mut changes = fixture.changes().await?;
    let outcome = changes
        .apply_cli(entware::change_request(operation)?)
        .await
        .map(|result| result.unsaved);
    drop(changes);
    Ok(outcome)
}

/// Whether the fake router heard the CLI line `line`.
fn heard(fixture: &Fixture, line: &str) -> bool {
    fixture
        .handle()
        .request_log()
        .iter()
        .flat_map(|record| {
            record
                .commands()
                .flatten()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .any(|command| command == line)
}

/// One planner run against a router context.
type Planner = fn(&RouterCtx) -> DomainResult<EntwarePlan>;
