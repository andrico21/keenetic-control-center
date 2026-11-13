//! Step 8: the result of the apply and the final choice.
//!
//! Keep unsaved disarms the router's fail-safe timer and saves nothing; Save on the router
//! saves the verified settings; Roll back restores the saved configuration (the router
//! name typed; it needs `Destructive`). The countdown shows how long the timer still
//! runs. An apply that changed nothing to keep offers Back to the preview or Finish.

use askama::Template;
use kcc_app::permissions::Permission;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{access::Visit, events::failure_text};
use crate::{
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::allowed},
};

/// What keeping the settings unsaved needs on the target: disarming the timer.
pub(super) const KEEP: [Permission; 2] = [Permission::Migrate, Permission::Write];

/// What saving the settings needs on the target.
pub(super) const SAVE: [Permission; 2] = [Permission::Migrate, Permission::Save];

/// What a rollback needs on the target.
pub(super) const ROLLBACK: [Permission; 2] = [Permission::Migrate, Permission::Destructive];

/// Failures after which nothing on the router changed: the apply can start again.
const BEFORE_CHANGES: [&str; 11] = [
    "UnverifiedFirmwareTier",
    "ModeUnknown",
    "Drift",
    "SameRouter",
    "Source",
    "Firmware",
    "AgreementRequired",
    "PasswordRequired",
    "Validation",
    "Workflow",
    "Job",
];

/// Where a button's answer goes: the step, or the dialog (the rollback asks first).
const STEP: &str = "#wizard-step";

/// The shared dialog.
const DIALOG: &str = "#dialog-content";

/// One of the step's buttons.
struct Act {
    /// What it posts to: `keep`, `save`, `retry`, `rollback` or `close`.
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
#[template(path = "partials/presets_results.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// Notice tone of the result.
    tone: &'static str,
    /// The result.
    message: String,
    /// What the apply did.
    facts: Vec<(String, String)>,
    /// Whether the settings wait under the router's timer.
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
        let user = visit.services().user();
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
            (Some((true, false)), _) => ("success", keys::WEB_PRESETS_APPLIED),
            (_, Some(name)) => ("error", failure_text(name)),
            (Some(_), None) => ("error", keys::WEB_PRESETS_FAILURE_FAILED),
            (None, None) => ("error", keys::WEB_PRESETS_RUN_INTERRUPTED),
        };
        let pending = matches!(held, Some((_, false)));
        let verified = matches!(held, Some((true, false)));
        let rollback = pending && allowed(user, target, &ROLLBACK);
        let failed_before = held.is_none()
            && failure
                .as_deref()
                .is_some_and(|name| BEFORE_CHANGES.contains(&name));
        let shown = [
            (
                verified && allowed(user, target, &KEEP),
                ("keep", keys::WEB_PRESETS_KEEP, "primary", STEP),
            ),
            (
                verified && allowed(user, target, &SAVE),
                ("save", keys::WEB_PRESETS_SAVE_ROUTER, "secondary", STEP),
            ),
            (
                failed_before,
                ("retry", keys::WEB_MIGRATE_RETRY, "secondary", STEP),
            ),
            (
                rollback,
                ("rollback", keys::MIGRATE_ROLLBACK, "danger-ghost", DIALOG),
            ),
            (!pending, ("close", keys::WEB_MIGRATE_CLOSE, "ghost", STEP)),
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
pub(super) fn facts(applied: usize, failed: usize, locale: Locale) -> Vec<(String, String)> {
    [
        (keys::WEB_MIGRATE_COUNT_APPLIED, applied),
        (keys::WEB_MIGRATE_COUNT_REFUSED, failed),
    ]
    .into_iter()
    .map(|(key, count)| (tr(locale, key, None), count.to_string()))
    .collect()
}
