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
//! its own to pass.

use axum::response::{IntoResponse as _, Response};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, RouterCtx};
use kcc_i18n::{bundle::MessageKey, locale::Locale};

use super::{
    action::Action,
    change::Change,
    confirm::Resubmit,
    failure::plan_failure,
    family::Family,
    outcome::{Failure, Outcome},
    request::{Params, missing},
    respond::{changed, retarget},
};

#[cfg(test)]
mod submit_tests;

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
    /// The change that carries them.
    change: Change,
}

impl Planned {
    /// `change`, which carries `operations`, at the highest risk among them.
    pub(crate) fn of(operations: &[ChangeOp], change: Change) -> Self {
        let risk = operations
            .iter()
            .map(|operation| operation.risk)
            .max()
            .unwrap_or(Risk::Read);
        Self { risk, change }
    }

    /// The risk the change runs at, and the change.
    pub(super) fn into_parts(self) -> (Risk, Change) {
        (self.risk, self.change)
    }
}

/// When the submission asks for a confirmation.
enum Ask {
    /// Never: the change's risk needs none.
    Never,
    /// Once the values passed their check, before anything is read from the router, at
    /// `risk`.
    First {
        /// The risk the confirmation is for.
        risk: Risk,
        /// What confirming sends.
        resubmit: Resubmit,
    },
    /// Once the change is planned, at the planned risk.
    Planned(Resubmit),
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

    /// Checks the values with `check`, plans the change with `plan`, runs it at the
    /// planned risk and, after a success, reads the page's region back with `refresh`.
    // NOT cancel-safe: see `Action::run_planned`.
    pub(crate) async fn submit<T, C, P, R>(self, check: C, plan: P, refresh: R) -> Response
    where
        C: FnOnce(&Params) -> Result<T, Invalid>,
        P: AsyncFnOnce(T, &RouterCtx) -> Result<Planned, DomainError>,
        R: AsyncFnOnce(&RouterCtx) -> Option<String>,
    {
        let Self {
            action,
            params,
            form,
            ask,
            landing,
        } = self;
        let locale = action.locale();
        let checked = match check(params) {
            Ok(checked) => checked,
            Err(invalid) => {
                action.abandon("validation_failed").await;
                return form.answer_invalid(invalid, locale);
            }
        };
        let confirmation = params.confirmation();
        let ask_planned = match ask {
            Ask::Never => None,
            Ask::First { risk, resubmit } => {
                if let Some(prompt) = action.confirm(risk, &confirmation, resubmit) {
                    return prompt;
                }
                None
            }
            Ask::Planned(resubmit) => Some(resubmit),
        };
        let domain = match action.context().await {
            Ok(domain) => domain,
            Err(answer) => return answer.into_response(),
        };
        let planned = match plan(checked, &domain).await {
            Ok(planned) => planned,
            Err(error) => {
                let failure = plan_failure(Family::Changes, locale, &error);
                action.abandon(failure.audit()).await;
                return land(form.answer_refused(failure, locale), landing);
            }
        };
        if let Some(resubmit) = ask_planned
            && let Some(prompt) = action.confirm(planned.risk, &confirmation, resubmit)
        {
            return prompt;
        }
        let outcome = action.run_planned(planned).await;
        let refreshed = if outcome.succeeded() {
            refresh(&domain).await
        } else {
            None
        };
        land(changed(outcome, refreshed, None, locale), landing)
    }
}

/// `answer`, shown in `landing` when the submission names one.
fn land(answer: Response, landing: Option<&'static str>) -> Response {
    match landing {
        Some(target) => retarget(answer, target),
        None => answer,
    }
}
