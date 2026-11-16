//! What a planned change runs: a change the workflow sends, or the domain's own work on
//! the leased change set, such as a write the domain reads back itself.

use core::pin::Pin;

use kcc_app::workflow::{ChangeSet, WorkflowError};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, RouterCtx};

use super::{
    super::{
        change::{Applied, Change},
        confirm::Stakes,
    },
    Planned,
};

/// The domain's work running on the leased change set, as a page hands it over.
pub(crate) type Working<'set> =
    Pin<Box<dyn Future<Output = Result<Applied, WorkflowError>> + Send + 'set>>;

/// The domain's work on the leased change set, started with the set and the router's
/// domain context.
pub(crate) type Work =
    Box<dyn for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send>;

/// What a planned change runs.
pub(crate) enum Job {
    /// A change the workflow sends.
    Change(Change),
    /// The domain's own work.
    Work(Work),
}

impl Planned {
    /// `change`, which carries `operations`, at the highest risk among them; inside the
    /// recovery timer when one of them is a management change.
    pub(crate) fn of(operations: &[ChangeOp], change: Change) -> Self {
        Self {
            stakes: stakes(operations),
            job: Job::Change(change),
        }
    }

    /// `work`, the domain's own run of `operations` on the leased change set (it sends
    /// them and reads them back itself), at the highest risk among them; inside the
    /// recovery timer when one of them is a management change.
    pub(crate) fn working<W>(operations: &[ChangeOp], work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
    {
        Self {
            stakes: stakes(operations),
            job: Job::Work(Box::new(work)),
        }
    }

    /// `work` at the operation's own risk, as its domain describes it: for work the
    /// domain plans no operations for, such as a restart.
    pub(crate) fn described<W>(work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
    {
        // The run never goes below the operation's described risk.
        Self::assessed(Risk::Read, work)
    }

    /// `work` on the leased change set at `risk`, the risk the domain assessed for the
    /// objects the change touches.
    pub(crate) fn assessed<W>(risk: Risk, work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
    {
        Self {
            stakes: Stakes::new(risk),
            job: Job::Work(Box::new(work)),
        }
    }

    /// The stakes the change runs at, and what runs.
    pub(in crate::page_kit) fn into_parts(self) -> (Stakes, Job) {
        (self.stakes, self.job)
    }
}

/// The highest risk among `operations`, inside the recovery timer when one of them is a
/// management change.
fn stakes(operations: &[ChangeOp]) -> Stakes {
    let highest = operations
        .iter()
        .map(|operation| operation.risk)
        .max()
        .unwrap_or(Risk::Read);
    let management = operations
        .iter()
        .any(|operation| operation.risk == Risk::Management);
    Stakes::new(highest).with_management(management)
}
