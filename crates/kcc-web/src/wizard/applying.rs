//! What the engine's apply needs from a wizard.
//!
//! Its audit actions and words, the permissions its apply needs, how it builds the
//! engine's request, its preview with a reason, and what it records when the apply ended.
//!
//! The engine's handler (`apply`) asks, checks and audits, and its launcher (`launch`)
//! reserves the target, starts the job and records its end, the same for every wizard.

use alloc::collections::BTreeMap;

use kcc_app::permissions::Permission;
use kcc_i18n::bundle::MessageKey;
use kcc_migrate::apply::{ApplyError, ApplyReport, ApplyRequest};

use super::{finishing::Finishing, store::StoreError, visit::Visit};
use crate::{WebState, page_kit::respond::Answer};

/// Why an apply did not start.
pub(crate) enum Failure {
    /// The preview says why (the reason's key), and the audit log records the outcome.
    Refused(MessageKey, &'static str),
    /// The run's files could not be read or written.
    Broken(StoreError),
    /// The engine could not start the apply's job.
    NotStarted(ApplyError),
    /// The request has no server owner, so the apply could be cut off half-started.
    Unowned,
}

/// An apply ready to start: the engine's request and, for each planned setting by its
/// index, its source line number and redacted text.
pub(crate) struct Starting {
    /// The engine's request.
    request: ApplyRequest,
    /// The planned settings' line numbers and texts.
    texts: BTreeMap<usize, (usize, String)>,
}

impl Starting {
    /// The apply of `request`, whose planned settings read as `texts`.
    pub(crate) const fn new(
        request: ApplyRequest,
        texts: BTreeMap<usize, (usize, String)>,
    ) -> Self {
        Self { request, texts }
    }

    /// The request and the texts.
    pub(crate) fn into_parts(self) -> (ApplyRequest, BTreeMap<usize, (usize, String)>) {
        (self.request, self.texts)
    }
}

/// A wizard whose run applies its plan: implemented by the wizard's record.
pub(crate) trait Applying: Finishing {
    /// The audit action of Apply.
    const APPLY_AUDIT: &'static str;
    /// The audit action of the apply's end.
    const APPLY_END_AUDIT: &'static str;
    /// The dialog asking before the apply starts: title and text (both with `$router`
    /// and `$minutes`) and the button.
    const CONFIRM: (MessageKey, MessageKey, MessageKey);
    /// The reason shown while another run applies to the target.
    const BUSY: MessageKey;

    /// What the apply needs on the target.
    fn apply_permissions(&self) -> Vec<Permission>;

    /// The apply of the run `visit` opened, built from a fresh read of the target, with
    /// what it keeps for the run saved; refused when the plan is no longer the one the
    /// preview showed.
    fn prepare(
        visit: &mut Visit<'_, Self>,
        state: &WebState,
    ) -> impl Future<Output = Result<Starting, Failure>> + Send;

    /// The preview of the run `visit` opened again, with `reason`, as 422 in the step.
    fn refusal(
        visit: &Visit<'_, Self>,
        state: &WebState,
        reason: String,
    ) -> impl Future<Output = Answer> + Send;

    /// Records how the apply ended at `now`: the engine's report, or the error it failed
    /// with before it made one.
    fn record_end(&mut self, now: u64, outcome: Result<&ApplyReport, ApplyError>) {
        if let Some(run) = self.run_mut() {
            run.end(now, outcome);
        }
    }
}
