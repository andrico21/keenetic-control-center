//! One submitted change, end to end.
//!
//! The submitted values are checked, the change is planned with the domain, confirmed
//! when its risk asks for it, run at the risk the domain planned, and the page's region
//! is read back.
//!
//! A value that fails its check is answered by the page's form and audited
//! `validation_failed`. A change the domain could not plan is audited with its own reason
//! (`forbidden`, `failed`, a router error, the catalog's findings) and answered where the
//! form shows it. The change runs at the risk of the domain's plan: a page has no risk of
//! its own to pass. What runs is a change the workflow sends or the domain's own work on
//! the leased change set ([`Planned::working`]); values checked against what the router
//! has go through [`Submission::submit_reading`].

use core::mem;

use axum::response::{IntoResponse as _, Response};
use kcc_app::workflow::ChangeSet;
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, RouterCtx};
use kcc_i18n::{bundle::MessageKey, locale::Locale};

use self::{
    flow::{Ask, land},
    rejected::Rejected,
    work::{Job, Working},
};
use super::{
    action::Action,
    change::Change,
    confirm::Resubmit,
    failure::plan_failure,
    family::Family,
    outcome::{Failure, Outcome},
    request::{Params, missing},
    respond::changed,
};

mod flow;
pub(crate) mod rejected;
#[cfg(test)]
mod submit_tests;
pub(crate) mod work;

/// Submitted values that failed their check: each finding's field and the rule it broke.
pub(crate) struct Invalid(Vec<(&'static str, MessageKey)>);

impl Invalid {
    /// One finding: `field` broke `rule`.
    pub(crate) fn at(field: &'static str, rule: MessageKey) -> Self {
        Self(vec![(field, rule)])
    }

    /// The findings, in order.
    pub(crate) fn into_findings(self) -> Vec<(&'static str, MessageKey)> {
        self.0
    }
}

impl From<Vec<(&'static str, MessageKey)>> for Invalid {
    fn from(findings: Vec<(&'static str, MessageKey)>) -> Self {
        Self(findings)
    }
}

/// The page's form: how it answers values that failed their check, and a change the
/// domain could not plan.
pub(crate) trait Form: Sized {
    /// The form again, with each finding at its field.
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response;

    /// The answer to a change that could not be planned: the page's outcome region,
    /// unless the form shows it itself.
    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        changed(Outcome::failed(failure), None, None, locale)
    }

    /// The answer to a change that ran: `outcome`, then the page's region read back,
    /// `refreshed`.
    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<String>,
        locale: Locale,
    ) -> Response {
        changed(outcome, refreshed, None, locale)
    }
}

/// A submission without a form: values that fail their check name nothing the page has,
/// answered 404.
pub(crate) struct Formless;

impl Form for Formless {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        missing().into_response()
    }
}

/// A change the domain planned, at the risk of the domain's plan.
pub(crate) struct Planned {
    /// The highest risk of the planned operations.
    risk: Risk,
    /// What runs.
    job: Job,
}

impl Planned {
    /// `change`, which carries `operations`, at the highest risk among them.
    pub(crate) fn of(operations: &[ChangeOp], change: Change) -> Self {
        Self {
            risk: highest(operations),
            job: Job::Change(change),
        }
    }

    /// `work`, the domain's own run of `operations` on the leased change set (it sends
    /// them and reads them back itself), at the highest risk among them.
    pub(crate) fn working<W>(operations: &[ChangeOp], work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
    {
        Self::assessed(highest(operations), work)
    }

    /// `work` on the leased change set at `risk`, the risk the domain assessed for the
    /// objects the change touches.
    pub(crate) fn assessed<W>(risk: Risk, work: W) -> Self
    where
        W: for<'set> FnOnce(&'set mut ChangeSet, &'set RouterCtx) -> Working<'set> + Send + 'static,
    {
        Self {
            risk,
            job: Job::Work(Box::new(work)),
        }
    }

    /// The risk the change runs at, and what runs.
    pub(super) fn into_parts(self) -> (Risk, Job) {
        (self.risk, self.job)
    }
}

/// The highest risk among `operations`.
fn highest(operations: &[ChangeOp]) -> Risk {
    operations
        .iter()
        .map(|operation| operation.risk)
        .max()
        .unwrap_or(Risk::Read)
}

/// A form submitted to an opened operation.
pub(crate) struct Submission<'call, F> {
    /// The opened operation.
    action: Action<'call>,
    /// The submitted parameters.
    params: &'call Params,
    /// The page's form.
    form: F,
    /// When the submission asks for a confirmation.
    ask: Ask,
    /// Where the change's answer lands instead of the request's own target.
    landing: Option<&'static str>,
    /// Whether the page's region is read back after a failed change too.
    refresh_failed: bool,
}

impl<'call, F: Form> Submission<'call, F> {
    /// `params`, submitted from `form` to `action`.
    pub(crate) const fn new(action: Action<'call>, params: &'call Params, form: F) -> Self {
        Self {
            action,
            params,
            form,
            ask: Ask::Never,
            landing: None,
            refresh_failed: false,
        }
    }

    /// Asks for the confirmation a change of `risk` needs once the values passed their
    /// check, before anything is read from the router; confirming sends `resubmit`.
    pub(crate) fn confirming(mut self, risk: Risk, resubmit: Resubmit) -> Self {
        self.ask = Ask::First { risk, resubmit };
        self
    }

    /// Asks for the confirmation the planned change's risk needs before it runs;
    /// confirming sends `resubmit`.
    pub(crate) fn confirming_planned(mut self, resubmit: Resubmit) -> Self {
        self.ask = Ask::Planned(resubmit);
        self
    }

    /// Shows the answer to the change, refused or run, in `target`.
    pub(crate) const fn landing_in(mut self, target: &'static str) -> Self {
        self.landing = Some(target);
        self
    }

    /// Reads the page's region back after a failed change too, as after a success.
    pub(crate) const fn refreshing_after_failure(mut self) -> Self {
        self.refresh_failed = true;
        self
    }

    /// Checks the values with `check`, plans the change with `plan`, runs it at the
    /// planned risk and, after a success, reads the page's region back with `refresh`.
    // NOT cancel-safe: see `Action::run_planned`.
    pub(crate) async fn submit<T, C, P, R>(mut self, check: C, plan: P, refresh: R) -> Response
    where
        C: FnOnce(&Params) -> Result<T, Invalid>,
        P: AsyncFnOnce(T, &RouterCtx) -> Result<Planned, DomainError>,
        R: AsyncFnOnce(&RouterCtx) -> Option<String>,
    {
        let checked = match check(self.params) {
            Ok(checked) => checked,
            Err(invalid) => return self.invalid(invalid).await,
        };
        if let Some(prompt) = self.ask_first() {
            return prompt;
        }
        let domain = match self.action.context().await {
            Ok(domain) => domain,
            Err(answer) => return answer.into_response(),
        };
        self.carry(checked, &domain, (plan, refresh)).await
    }

    /// [`Self::submit`] with values checked against what the router has: `check` reads
    /// the router with the domain context and says why no change can follow, if so.
    // NOT cancel-safe: see `Action::run_planned`.
    pub(crate) async fn submit_reading<T, C, P, R>(
        mut self,
        check: C,
        plan: P,
        refresh: R,
    ) -> Response
    where
        C: AsyncFnOnce(&Params, &RouterCtx) -> Result<T, Rejected>,
        P: AsyncFnOnce(T, &RouterCtx) -> Result<Planned, DomainError>,
        R: AsyncFnOnce(&RouterCtx) -> Option<String>,
    {
        let domain = match self.action.context().await {
            Ok(domain) => domain,
            Err(answer) => return answer.into_response(),
        };
        let checked = match check(self.params, &domain).await {
            Ok(checked) => checked,
            Err(Rejected::Invalid(invalid)) => return self.invalid(invalid).await,
            Err(Rejected::Refused(failure)) => return self.refused(failure).await,
            Err(Rejected::Failed(failure)) => return self.failed(failure).await,
            Err(Rejected::Missing) => return missing().into_response(),
        };
        if let Some(prompt) = self.ask_first() {
            return prompt;
        }
        self.carry(checked, &domain, (plan, refresh)).await
    }

    /// The form's answer to values that failed their check, audited `validation_failed`.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn invalid(self, invalid: Invalid) -> Response {
        let locale = self.action.locale();
        self.action.abandon("validation_failed").await;
        self.form.answer_invalid(invalid, locale)
    }

    /// The answer to a change refused before it ran, audited with its reason.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn refused(self, failure: Failure) -> Response {
        let locale = self.action.locale();
        self.action.abandon(failure.audit()).await;
        land(self.form.answer_refused(failure, locale), self.landing)
    }

    /// The answer to a change what the router has rules out, in the outcome region,
    /// audited with its reason.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn failed(self, failure: Failure) -> Response {
        let locale = self.action.locale();
        self.action.abandon(failure.audit()).await;
        let answer = self
            .form
            .answer_changed(Outcome::failed(failure), None, locale);
        land(answer, self.landing)
    }

    /// The confirmation asked for before anything is read, while it is not given.
    fn ask_first(&mut self) -> Option<Response> {
        match mem::replace(&mut self.ask, Ask::Never) {
            Ask::First { risk, resubmit } => {
                self.action
                    .confirm(risk, &self.params.confirmation(), resubmit)
            }
            later @ (Ask::Never | Ask::Planned(_)) => {
                self.ask = later;
                None
            }
        }
    }

    /// Plans the `checked` values with `plan`, asks for the planned confirmation, runs
    /// the change and reads the page's region back with `refresh`.
    // NOT cancel-safe: see `Action::run_planned`.
    async fn carry<T, P, R>(
        self,
        checked: T,
        domain: &RouterCtx,
        (plan, refresh): (P, R),
    ) -> Response
    where
        P: AsyncFnOnce(T, &RouterCtx) -> Result<Planned, DomainError>,
        R: AsyncFnOnce(&RouterCtx) -> Option<String>,
    {
        let locale = self.action.locale();
        let planned = match plan(checked, domain).await {
            Ok(planned) => planned,
            Err(error) => {
                return self
                    .refused(plan_failure(Family::Changes, locale, &error))
                    .await;
            }
        };
        let Self {
            action,
            params,
            form,
            ask,
            landing,
            refresh_failed,
        } = self;
        if let Ask::Planned(resubmit) = ask
            && let Some(prompt) = action.confirm(planned.risk, &params.confirmation(), resubmit)
        {
            return prompt;
        }
        let outcome = action.run_planned(planned).await;
        let refreshed = if outcome.succeeded() || refresh_failed {
            refresh(domain).await
        } else {
            None
        };
        land(form.answer_changed(outcome, refreshed, locale), landing)
    }
}
