//! Step 8: the result of the apply and the final choice.
//!
//! Commit saves the verified changes; Roll back restores the saved configuration (the
//! router name typed; it needs `Destructive`). The countdown shows how long the router's
//! fail-safe timer still runs. An apply that changed nothing to keep offers to plan
//! again or to finish.

use askama::Template;
use kcc_app::permissions::Permission;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::apply::ApplyError;

use super::{access::Visit, preview::APPLY, run::recorded_text};
use crate::{
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::allowed},
};

/// What a rollback needs on the target.
pub(super) const ROLLBACK: [Permission; 2] = [Permission::Migrate, Permission::Destructive];

/// Failures after which nothing on the router changed: the apply can start again.
const BEFORE_CHANGES: [ApplyError; 11] = [
    ApplyError::UnverifiedFirmwareTier,
    ApplyError::ModeUnknown,
    ApplyError::Drift,
    ApplyError::SameRouter,
    ApplyError::Source,
    ApplyError::Firmware,
    ApplyError::AgreementRequired,
    ApplyError::PasswordRequired,
    ApplyError::Validation,
    ApplyError::Workflow,
    ApplyError::Job,
];

/// Where a button's answer goes: the step, or the dialog (the rollback asks first).
const STEP: &str = "#wizard-step";

/// The shared dialog.
const DIALOG: &str = "#dialog-content";

/// One of the step's buttons.
struct Act {
    /// What it posts to: `commit`, `replan`, `retry`, `rollback` or `close`.
    way: &'static str,
    /// Its label.
    label: String,
    /// Its button style, such as `primary`.
    style: &'static str,
    /// Where its answer goes.
    target: &'static str,
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_results.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// Notice tone of the result.
    tone: &'static str,
    /// The result.
    message: String,
    /// What the apply did.
    facts: Vec<(String, String)>,
    /// Whether the changes wait under the router's timer.
    pending: bool,
    /// Whether they wait but the role may not roll them back.
    rollback_forbidden: bool,
    /// The buttons, primary first.
    actions: Vec<Act>,
    /// Why the last choice failed.
    error: String,
}

impl Localize for Panel {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Panel {
    /// The results of `visit`'s apply.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>) -> Self {
        let services = visit.services();
        let user = services.user();
        let locale = user.locale();
        let record = visit.record();
        let target = record.target().unwrap_or_default();
        let ended = record.run().and_then(|run| run.ended().cloned());
        let held = match visit.session().live() {
            Some(live) => live
                .applier()
                .await
                .as_ref()
                .map(|applier| (applier.report().verified, applier.report().finished)),
            None => None,
        };
        let failure = ended
            .as_ref()
            .and_then(|end| end.failure().map(str::to_owned));
        let (tone, key) = match (&held, failure.as_deref()) {
            (Some((true, false)), _) => ("success", keys::MIGRATE_APPLY_VERIFIED),
            (_, Some(name)) => ("error", recorded_text(name)),
            (Some(_), None) => ("error", keys::MIGRATE_APPLY_FAILED),
            (None, None) => ("error", keys::WEB_MIGRATE_RUN_INTERRUPTED),
        };
        let pending = matches!(held, Some((_, false)));
        let known = failure.as_deref().and_then(ApplyError::from_name);
        let failed_before = |errors: &[ApplyError]| {
            held.is_none() && known.is_some_and(|error| errors.contains(&error))
        };
        let replan = failed_before(&[ApplyError::ReplanRequired]);
        let rollback = pending && allowed(user, target, &ROLLBACK);
        let shown = [
            (
                matches!(held, Some((true, false))) && allowed(user, target, APPLY),
                ("commit", keys::WEB_MIGRATE_COMMIT, "primary", STEP),
            ),
            (
                replan,
                ("replan", keys::WEB_MIGRATE_REPLAN, "primary", STEP),
            ),
            (
                failed_before(&BEFORE_CHANGES),
                ("retry", keys::WEB_MIGRATE_RETRY, "secondary", STEP),
            ),
            (
                rollback,
                ("rollback", keys::MIGRATE_ROLLBACK, "danger-ghost", DIALOG),
            ),
            (
                !pending && !replan,
                ("close", keys::WEB_MIGRATE_CLOSE, "ghost", STEP),
            ),
        ];
        Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            tone,
            message: tr(locale, key, None),
            facts: ended.map_or_else(Vec::new, |end| facts(end.applied(), end.failed(), locale)),
            pending,
            rollback_forbidden: pending && !rollback,
            actions: shown
                .into_iter()
                .filter(|(show, _)| *show)
                .map(|(_, button)| act(locale, button))
                .collect(),
            error: String::new(),
        }
    }

    /// The panel with the reason the last choice failed.
    pub(super) fn refusing(mut self, error: String) -> Self {
        self.error = error;
        self
    }
}

/// The button posting to `way`, labelled `key`, in `style`, answering into `target`.
fn act(
    locale: Locale,
    (way, key, style, target): (&'static str, MessageKey, &'static str, &'static str),
) -> Act {
    Act {
        way,
        label: tr(locale, key, None),
        style,
        target,
    }
}

/// The counts of an apply that sent `applied` settings and had `failed` refused.
fn facts(applied: usize, failed: usize, locale: Locale) -> Vec<(String, String)> {
    [
        (keys::WEB_MIGRATE_COUNT_APPLIED, applied),
        (keys::WEB_MIGRATE_COUNT_REFUSED, failed),
    ]
    .into_iter()
    .map(|(key, count)| (tr(locale, key, None), count.to_string()))
    .collect()
}
