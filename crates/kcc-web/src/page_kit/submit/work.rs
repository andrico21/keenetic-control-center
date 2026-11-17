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

/// [`Working`] whose failure also says what the page shows beyond its outcome.
pub(crate) type Reporting<'set> =
    Pin<Box<dyn Future<Output = Result<Applied, Stopped>> + Send + 'set>>;

/// The domain's work on the leased change set, started with the set and the router's
/// domain context.
pub(crate) type Work =
    Box<dyn for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Reporting<'set> + Send>;

/// What a page's work says beyond the kit's outcome, handed back with the outcome.
#[derive(Debug)]
pub(crate) enum Report {
    /// A sentence shown with the outcome, such as the step a failed change stopped at.
    Note(String),
    /// The router cleared every static route of the family instead of removing one, and
    /// the routes it had were put back.
    RoutesWiped {
        /// Whether the router has unsaved changes now.
        unsaved: bool,
    },
    /// The routing table did not lose exactly the one route.
    RouteCountMismatch,
}

/// Work that stopped: its workflow error, and what the page shows beyond it.
pub(crate) struct Stopped {
    /// Why the work stopped.
    error: WorkflowError,
    /// What the page shows beyond the error.
    report: Option<Report>,
}

impl Stopped {
    /// Work that stopped with `error`, the page showing `report` beyond it.
    pub(crate) const fn reporting(error: WorkflowError, report: Option<Report>) -> Self {
        Self { error, report }
    }

    /// Why the work stopped; what the page shows beyond it goes to `report`.
    pub(in crate::page_kit) fn into_error(self, report: &mut Option<Report>) -> WorkflowError {
        *report = self.report;
        self.error
    }
}

impl From<WorkflowError> for Stopped {
    fn from(error: WorkflowError) -> Self {
        Self::reporting(error, None)
    }
}

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
            job: Job::Work(plain(work)),
        }
    }

    /// [`Self::working`] with work whose failure also says what the page shows beyond the
    /// outcome; the outcome carries it ([`super::super::outcome::Outcome::take_report`]).
    pub(crate) fn reporting<W>(operations: &[ChangeOp], work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Reporting<'set>
            + Send
            + 'static,
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
            job: Job::Work(plain(work)),
        }
    }

    /// The stakes the change runs at, and what runs.
    pub(in crate::page_kit) fn into_parts(self) -> (Stakes, Job) {
        (self.stakes, self.job)
    }
}

/// `work`, whose failure says nothing beyond its workflow error.
fn plain<W>(work: W) -> Work
where
    W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
{
    boxed(move |changes, context| {
        Box::pin(async move { work(changes, context).await.map_err(Stopped::from) })
    })
}

/// `work` as the kit keeps it.
fn boxed<W>(work: W) -> Work
where
    W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Reporting<'set> + Send + 'static,
{
    Box::new(work)
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
