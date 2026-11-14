//! What a planned change runs: a change the workflow sends, or the domain's own work on
//! the leased change set, such as a write the domain reads back itself.

use core::pin::Pin;

use kcc_app::workflow::{ChangeSet, WorkflowError};
use kcc_domain::RouterCtx;

use super::super::change::{Applied, Change};

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
