//! Step 8: the result of the apply and the final choice.
//!
//! The wizard's keep buttons (a migration commits; a preset run keeps unsaved or saves)
//! finish the verified changes; Roll back restores the saved configuration (the router
//! name typed; it needs `Destructive`). The countdown shows how long the router's
//! fail-safe timer still runs. An apply that changed nothing to keep offers to plan again
//! (a migration that needs a new plan), go back to the preview, or finish.

use askama::Template;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::apply::ApplyError;

use super::{
    finishing::{Finishing, ROLLBACK},
    visit::Visit,
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::allowed},
};

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
    /// What it posts to, such as `commit`, `retry`, `rollback` or `close`.
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
#[template(path = "partials/wizard_results.html")]
pub(crate) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Where the wizard's run pages are.
    prefix: &'static str,
    /// Run id.
    id: String,
    /// Notice tone of the result.
    tone: &'static str,
    /// The result.
    message: String,
    /// What the apply did.
    facts: Vec<(String, String)>,
    /// Whether the changes wait under the router's timer.
    pending: bool,
    /// The sentence under the counts while they wait, if the wizard has one.
    waiting: Option<String>,
    /// The note shown when they wait but the role may not roll them back.
    forbidden: Option<String>,
    /// The buttons, primary first.
    actions: Vec<Act>,
    /// Why the last choice failed.
    error: String,
}

localized!(Panel);

impl Panel {
    /// The results of `visit`'s apply.
    // cancel-safe: reads only.
    pub(crate) async fn new<F>(visit: &Visit<'_, F>) -> Self
    where
        F: Finishing,
    {
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
            (Some((true, false)), _) => ("success", F::VERIFIED),
            (_, Some(name)) => ("error", F::recorded_text(name)),
            (Some(_), None) => ("error", F::FAILED),
            (None, None) => ("error", F::INTERRUPTED),
        };
        let pending = matches!(held, Some((_, false)));
        let verified = matches!(held, Some((true, false)));
        let known = failure.as_deref().and_then(ApplyError::from_name);
        let failed_before = |errors: &[ApplyError]| {
            held.is_none() && known.is_some_and(|error| errors.contains(&error))
        };
        let replan = F::REPLANS && failed_before(&[ApplyError::ReplanRequired]);
        let rollback = pending && allowed(user, target, &ROLLBACK);
        let keeping = F::KEEPING.iter().map(|&(choice, way, label, style)| {
            let permitted =
                F::choice(choice).is_some_and(|(_, needed, _)| allowed(user, target, &needed));
            (verified && permitted, (way, label, style, STEP))
        });
        let shown = [
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
            prefix: F::PREFIX,
            id: record.id().to_owned(),
            tone,
            message: tr(locale, key, None),
            facts: ended.map_or_else(Vec::new, |end| facts(end.applied(), end.failed(), locale)),
            pending,
            waiting: F::WAITING.map(|text| tr(locale, text, None)),
            forbidden: (pending && !rollback).then(|| tr(locale, F::ROLLBACK_FORBIDDEN, None)),
            actions: keeping
                .chain(shown)
                .filter(|(show, _)| *show)
                .map(|(_, button)| act(locale, button))
                .collect(),
            error: String::new(),
        }
    }

    /// The panel with the reason the last choice failed.
    pub(crate) fn refusing(mut self, error: String) -> Self {
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
