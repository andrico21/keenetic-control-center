//! What the Entware settings changes share: their operations, how a refused value is
//! answered, and the one run from plan to read-back.
//!
//! Each change is planned by the Entware domain, which checks the permission, the
//! confirmation and the value grammar; the kit asks for the confirmation the planned risk
//! needs (the fail-safe timer for DNS override) and the region is read back after it ran.

use core::future::ready;

use axum::response::{IntoResponse as _, Response};
use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError, Result as DomainResult, RouterCtx,
    entware::{
        self,
        models::{EntwarePlan, EntwareWarning},
    },
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    entware::Viewer,
    shared::{refused, value},
};
use crate::page_kit::{
    action::{Action, Operation},
    change::Change,
    confirm::Resubmit,
    outcome::Failure,
    request::{Params, missing},
    respond::Answer,
    submit::{self, Invalid, Planned, Submission, unplanned::Unplanned},
};

/// Turning chroot on or off, audited as `web.entware_chroot`.
pub(crate) const CHROOT: Operation = Operation::planned(
    "opkg chroot",
    (Permission::Write, Risk::Write),
    "web.entware_chroot",
);

/// Setting the time zone, audited as `web.entware_timezone`.
pub(crate) const TIMEZONE: Operation = Operation::planned(
    "opkg timezone",
    (Permission::Write, Risk::Write),
    "web.entware_timezone",
);

/// Turning DNS override on or off, audited as `web.entware_dns_override`.
pub(crate) const DNS_OVERRIDE: Operation = Operation::planned(
    "opkg dns-override",
    (Permission::Write, Risk::Management),
    "web.entware_dns_override",
);

/// Setting the startup script, audited as `web.entware_initrc`.
pub(crate) const INITRC: Operation = Operation::planned(
    "opkg initrc",
    (Permission::Destructive, Risk::Destructive),
    "web.entware_initrc",
);

/// Removing Entware (`no opkg disk`), audited as `web.entware_remove`.
pub(crate) const REMOVE: Operation = Operation::planned(
    "opkg disk",
    (Permission::Destructive, Risk::Destructive),
    "web.entware_remove",
);

/// The page's answers to a change the domain refused: a value outside its grammar names
/// the field's rule, any other refusal shows in the outcome region.
struct Settings {
    /// The rule a refused value broke.
    rule: MessageKey,
}

impl submit::Form for Settings {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        missing().into_response()
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        refused(&failure, locale)
    }

    fn answer_unplanned(
        self,
        unplanned: Unplanned<'_>,
        locale: Locale,
    ) -> impl Future<Output = Response> {
        let failure = if matches!(unplanned.error(), DomainError::InvalidCliToken) {
            Failure::new(tr(locale, self.rule, None), "validation_failed")
        } else {
            unplanned.into_failure()
        };
        ready(refused(&failure, locale))
    }
}

/// One settings change: where it is sent again, the confirmation it asks for before
/// anything is read, the rule a refused value broke and who reads the region back.
pub(super) struct Course<'call> {
    /// The request sent again by a confirmation.
    again: Resubmit,
    /// The confirmation asked for first, if any.
    first: Option<Risk>,
    /// The rule a refused value broke.
    rule: MessageKey,
    /// Who reads the region back after the change.
    viewer: Viewer<'call>,
}

impl<'call> Course<'call> {
    /// A change sent again by `again`, whose region `viewer` reads back; it asks nothing
    /// first and a refused value breaks [`keys::WEB_SYSTEM_ENTWARE_REFUSED`].
    pub(super) const fn new(again: Resubmit, viewer: Viewer<'call>) -> Self {
        Self {
            again,
            first: None,
            rule: keys::WEB_SYSTEM_ENTWARE_REFUSED,
            viewer,
        }
    }

    /// Also asks for the confirmation of `risk` before anything is read.
    pub(super) const fn asking_first(mut self, risk: Risk) -> Self {
        self.first = Some(risk);
        self
    }

    /// A refused value breaks `rule`.
    pub(super) const fn refusing_with(mut self, rule: MessageKey) -> Self {
        self.rule = rule;
        self
    }
}

/// Plans the change with `plan` and runs it as `action`, asking first as `course` says;
/// the region is read back after a success.
// NOT cancel-safe: see `Submission::submit`.
pub(super) async fn run<P>(
    action: Action<'_>,
    pairs: Vec<(String, String)>,
    course: Course<'_>,
    plan: P,
) -> Response
where
    P: FnOnce(&RouterCtx) -> DomainResult<EntwarePlan>,
{
    let Course {
        again,
        first,
        rule,
        viewer,
    } = course;
    let params = Params::of(pairs);
    let mut submission = Submission::new(action, &params, Settings { rule }, again);
    if let Some(risk) = first {
        submission = submission.confirming(risk);
    }
    submission
        .submit(
            |_params| Ok(()),
            async |(), ctx| {
                let planned = plan(ctx)?;
                let request = entware::change_request(&planned.operation)?;
                Ok(Planned::of(&[planned.operation], Change::Cli(request)))
            },
            async |ctx| viewer.refreshed(ctx).await,
        )
        .await
}

/// `on=true|false` of a request.
///
/// # Errors
///
/// Answers 404 for any other value.
pub(super) fn switch(pairs: &[(String, String)]) -> Result<bool, Answer> {
    match value(pairs, "on") {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) | None => Err(missing()),
    }
}

/// The message of one warning the domain planned with a change.
pub(super) const fn warning(said: EntwareWarning) -> MessageKey {
    match said {
        EntwareWarning::ChrootStopsSshManagement => keys::WEB_SYSTEM_ENTWARE_CHROOT_WARNING,
        EntwareWarning::DnsOverrideStopsRouterDns => keys::WEB_SYSTEM_ENTWARE_DNS_WARNING,
        _ => keys::WEB_SYSTEM_ENTWARE_WARNING_OTHER,
    }
}
