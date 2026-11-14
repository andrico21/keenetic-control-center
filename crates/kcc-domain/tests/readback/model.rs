//! Row model and driver of the read-back table.

use core::pin::Pin;

use kcc_app::workflow::{ChangeRequest, ChangeSet, CliChangeRequest, WorkflowError};
use kcc_domain::{ChangeOp, RouterCtx, clients};
use kcc_testkit::{FaultInjection, model::Firmware};

use crate::support::{Fixture, TestResult};

/// One planned write, in the transport its domain applies it with.
pub(crate) enum Step {
    /// A structured RCI write.
    Rci(ChangeRequest),
    /// A CLI write.
    Cli(CliChangeRequest),
    /// A hotspot policy write, which also verifies through the clients domain.
    Clients(ChangeOp),
}

/// The writes a row plans against a running router.
pub(crate) type Steps<'ctx> = Pin<Box<dyn Future<Output = TestResult<Vec<Step>>> + Send + 'ctx>>;

/// A fresh router read that answers whether the expected state is visible.
pub(crate) type Check<'ctx> = Pin<Box<dyn Future<Output = TestResult<bool>> + Send + 'ctx>>;

/// How a failed verification names its field.
pub(crate) enum Field {
    /// The field contains the text.
    Contains(&'static str),
    /// The field is exactly the text.
    Exact(&'static str),
    /// The field starts with the text.
    StartsWith(&'static str),
}

impl Field {
    /// Whether `found` is the field this row expects.
    fn matches(&self, found: &str) -> bool {
        match self {
            Self::Contains(text) => found.contains(text),
            Self::Exact(text) => found == *text,
            Self::StartsWith(text) => found.starts_with(text),
        }
    }
}

/// What a row expects of its writes.
pub(crate) enum Expect {
    /// The router acknowledges the write at `path` without applying it: every write must
    /// fail verification naming `field`.
    Silent {
        /// Fake-router path whose writes are ignored.
        path: &'static str,
        /// The failed field every verification names.
        field: Field,
    },
    /// The router applies the writes: each is read back and reported unsaved.
    Saved {
        /// A further router read that must hold once the last write is read back.
        after: Option<fn(&RouterCtx) -> Check<'_>>,
    },
}

/// One read-back row.
pub(crate) struct Row {
    /// Identifies the row in every assertion message.
    name: &'static str,
    /// Plans the row's writes.
    plan: fn(&RouterCtx, Firmware) -> Steps<'_>,
    /// The expected outcome.
    expect: Expect,
}

impl Row {
    /// A row named `name` that plans with `plan` and expects `expect`.
    pub(crate) const fn new(
        name: &'static str,
        plan: fn(&RouterCtx, Firmware) -> Steps<'_>,
        expect: Expect,
    ) -> Self {
        Self { name, plan, expect }
    }

    /// Whether the row injects an ignored-write fault.
    pub(crate) const fn is_silent(&self) -> bool {
        matches!(self.expect, Expect::Silent { path: _, field: _ })
    }
}

/// Applies `step` and returns whether the router reports the change unsaved.
async fn apply(
    step: Step,
    changes: &mut ChangeSet,
    ctx: &RouterCtx,
) -> Result<bool, WorkflowError> {
    match step {
        Step::Rci(request) => changes.apply(request).await.map(|result| result.unsaved),
        Step::Cli(request) => changes
            .apply_cli(request)
            .await
            .map(|result| result.unsaved),
        Step::Clients(operation) => clients::apply(changes, ctx, &operation)
            .await
            .map(|result| result.unsaved),
    }
}

/// Runs `row` against a fresh fixture on `firmware`.
pub(crate) async fn run(row: &Row, firmware: Firmware) -> TestResult {
    let name = row.name;
    let fixture = match &row.expect {
        Expect::Silent { path, field: _ } => {
            Fixture::spawn_with_faults(firmware, FaultInjection::default().silent_noop_path(*path))
                .await?
        }
        Expect::Saved { after: _ } => Fixture::spawn(firmware).await?,
    };
    let steps = (row.plan)(fixture.context(), firmware).await?;
    assert!(
        !steps.is_empty(),
        "{name} on {firmware:?}: no writes planned"
    );
    let mut held = None;
    for step in steps {
        drop(held.take());
        let mut changes = fixture.changes().await?;
        let outcome = apply(step, &mut changes, fixture.context()).await;
        match &row.expect {
            Expect::Silent { path: _, field } => assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field: failed }) if field.matches(failed)),
                "{name} on {firmware:?}: an ignored write must fail verification: {outcome:?}"
            ),
            Expect::Saved { after: _ } => {
                let unsaved =
                    outcome.map_err(|error| format!("{name} on {firmware:?}: {error}"))?;
                assert!(
                    unsaved,
                    "{name} on {firmware:?}: the write is not reported unsaved"
                );
            }
        }
        held = Some(changes);
    }
    if let Expect::Saved { after: Some(check) } = &row.expect {
        assert!(
            check(fixture.context()).await?,
            "{name} on {firmware:?}: the read-back state is not visible"
        );
    }
    drop(held);
    fixture.shutdown().await?;
    Ok(())
}
