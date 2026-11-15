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
//! has go through [`Submission::submit_reading`]. The page's form answers each end: values
//! that failed their check, a change refused before it ran, and a change that ran, whose
//! outcome the form may recast, such as a success's headline.

use axum::response::{IntoResponse as _, Response};
use kcc_catalog::Risk;
use kcc_domain::{DomainError, RouterCtx};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use self::{
    flow::{Ask, Course},
    rejected::Rejected,
    unplanned::Unplanned,
    work::Job,
};
use super::{
    action::Action,
    confirm::Resubmit,
    failure::plan_failure,
    family::Family,
    outcome::{Failure, Outcome},
    request::{Params, missing},
    respond::{Answer, changed},
};

#[cfg(test)]
mod answer_tests;
mod flow;
pub(crate) mod rejected;
#[cfg(test)]
mod submit_tests;
pub(crate) mod unplanned;
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

    /// The answer to a change the domain could not plan: as any refusal, unless the
    /// form's words depend on the domain's error or on what the router has.
    async fn answer_unplanned(self, unplanned: Unplanned<'_>, locale: Locale) -> Response {
        self.answer_refused(unplanned.into_failure(), locale)
    }

    /// The answer to a change that ran: `outcome`, then the page's region read back,
    /// `refreshed`. A form that recasts the outcome, such as a success's headline, does
    /// it here.
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

/// A change the domain planned, at the risk of the domain's plan; built in the `work`
/// module, with what it runs.
pub(crate) struct Planned {
    /// The highest risk of the planned operations.
    risk: Risk,
    /// What runs.
    job: Job,
}

/// A form submitted to an opened operation.
pub(crate) struct Submission<'call, F> {
    /// The opened operation.
    action: Action<'call>,
    /// The submitted parameters.
    params: &'call Params,
    /// The page's form.
    form: F,
    /// When it asks for a confirmation, where its answers land, what it reads back.
    course: Course,
}

impl<'call, F: Form> Submission<'call, F> {
    /// `params`, submitted from `form` to `action`.
    pub(crate) const fn new(action: Action<'call>, params: &'call Params, form: F) -> Self {
        Self {
            action,
            params,
            form,
            course: Course::new(),
        }
    }

    /// Asks for the confirmation a change of `risk` needs once the values passed their
    /// check, before anything is read from the router; confirming sends `resubmit`.
    pub(crate) fn confirming(mut self, risk: Risk, resubmit: Resubmit) -> Self {
        self.course.asking(Ask::First { risk, resubmit });
        self
    }

    /// Asks for the confirmation the planned change's risk needs before it runs;
    /// confirming sends `resubmit`.
    pub(crate) fn confirming_planned(mut self, resubmit: Resubmit) -> Self {
        self.course.asking(Ask::Planned(resubmit));
        self
    }

    /// Shows the answer to the change, refused or run, in `target`.
    pub(crate) const fn landing_in(mut self, target: &'static str) -> Self {
        self.course.landing_in(target);
        self
    }

    /// Shows the answer to a change that ran in `target`; a refusal stays where the
    /// request targets.
    pub(crate) const fn landing_run_in(mut self, target: &'static str) -> Self {
        self.course.landing_run_in(target);
        self
    }

    /// Reads the page's region back after a failed change too, as after a success.
    pub(crate) const fn refreshing_after_failure(mut self) -> Self {
        self.course.refreshing_after_failure();
        self
    }

    /// Checks the values with `check` for a page that makes no change of its own, such
    /// as a job start: the action and the checked values, to go on with.
    ///
    /// # Errors
    ///
    /// The form's answer to values that failed their check, audited `validation_failed`.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn checked<T, C>(self, check: C) -> Result<(Action<'call>, T), Answer>
    where
        C: FnOnce(&Params) -> Result<T, Invalid>,
    {
        match check(self.params) {
            Ok(checked) => Ok((self.action, checked)),
            Err(invalid) => Err(self.invalid(invalid).await.into()),
        }
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
            Err(Rejected::Unchanged) => return self.unchanged().await,
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
        self.course
            .refused(self.form.answer_refused(failure, locale))
    }

    /// The answer to a change the domain refused to plan with `error`, audited with its
    /// reason.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn unplanned(self, error: &DomainError, domain: &RouterCtx) -> Response {
        let locale = self.action.locale();
        let failure = plan_failure(Family::Changes, locale, error);
        self.action.abandon(failure.audit()).await;
        let unplanned = Unplanned::new(error, failure, domain);
        let answer = self.form.answer_unplanned(unplanned, locale).await;
        self.course.refused(answer)
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
        self.course.refused(answer)
    }

    /// The answer to values the router already has: nothing was sent, audited
    /// `unchanged`.
    // NOT cancel-safe: an abandoned append may still be written.
    async fn unchanged(self) -> Response {
        let locale = self.action.locale();
        self.action.abandon("unchanged").await;
        let headline = tr(locale, keys::WEB_SYSTEM_UNCHANGED, None);
        let answer = self
            .form
            .answer_changed(Outcome::info(headline, "unchanged"), None, locale);
        self.course.refused(answer)
    }

    /// The confirmation asked for before anything is read, while it is not given.
    fn ask_first(&mut self) -> Option<Response> {
        let (risk, resubmit) = self.course.first()?;
        self.action
            .confirm(risk, &self.params.confirmation(), resubmit)
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
        let planned = match plan(checked, domain).await {
            Ok(planned) => planned,
            Err(error) => return self.unplanned(&error, domain).await,
        };
        let locale = self.action.locale();
        let Self {
            action,
            params,
            form,
            mut course,
        } = self;
        if let Some(resubmit) = course.planned()
            && let Some(prompt) = action.confirm(planned.risk, &params.confirmation(), resubmit)
        {
            return prompt;
        }
        let outcome = action.run_planned(planned).await;
        let refreshed = if course.reads_back(outcome.succeeded()) {
            refresh(domain).await
        } else {
            None
        };
        course.ran(form.answer_changed(outcome, refreshed, locale))
    }
}
