//! A preset run's apply, for the engine's `crate::wizard::apply`.
//!
//! Its words, the permissions it needs, the engine's request built again from a fresh
//! read of the target (refused when it is not the plan the preview showed), the preview
//! with a reason, and the new WireGuard public keys recorded at its end.

use alloc::collections::BTreeMap;

use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::{ApplyError, ApplyReport, ApplyWarning};

use super::{
    access::Visit,
    lines::redacted,
    plan::Basis,
    preview::{Panel, apply_permissions},
    record::Record,
};
use crate::{
    WebState,
    page_kit::respond::Answer,
    wizard::{
        analysis::Problem,
        applying::{Applying, Failure, Starting},
        flow::Flow as _,
        screen,
    },
};

impl Applying for Record {
    const APPLY_AUDIT: &'static str = "web.preset_apply";
    const APPLY_END_AUDIT: &'static str = "web.preset_apply_end";
    const CONFIRM: (MessageKey, MessageKey, MessageKey) = (
        keys::WEB_PRESETS_APPLY_CONFIRM_TITLE,
        keys::WEB_PRESETS_APPLY_CONFIRM_TEXT,
        keys::WEB_PRESETS_APPLY_BUTTON,
    );
    const BUSY: MessageKey = keys::WEB_PRESETS_APPLY_BUSY;

    fn apply_permissions(&self) -> Vec<Permission> {
        apply_permissions()
    }

    fn prepare(
        visit: &mut Visit<'_>,
        state: &WebState,
    ) -> impl Future<Output = Result<Starting, Failure>> + Send {
        prepare(visit, state)
    }

    fn refusal(
        visit: &Visit<'_>,
        state: &WebState,
        reason: String,
    ) -> impl Future<Output = Answer> + Send {
        refusal(visit, state, reason)
    }

    fn record_end(&mut self, now: u64, outcome: Result<&ApplyReport, ApplyError>) {
        if let Some(run) = self.run_mut() {
            run.end(now, outcome);
        }
        if let Ok(known) = outcome {
            let (keys, kept) = wireguard(known);
            self.set_keys(keys, kept);
        }
    }
}

/// The apply of `visit`, planned again from a fresh read of the target.
///
/// # Errors
///
/// Returns why it cannot start: the target cannot be read, the plan cannot be built, the
/// plan is not the one the preview showed (the preview moves on to the new one), or the
/// record cannot be written.
// NOT cancel-safe: dropped, the record may still be written.
async fn prepare(visit: &mut Visit<'_>, state: &WebState) -> Result<Starting, Failure> {
    let services = visit.services();
    visit.session().forget();
    let basis = Basis::of(visit).await.map_err(|problem| match problem {
        Problem::Unreachable => {
            Failure::Refused(keys::WEB_MIGRATE_PROBLEM_UNREACHABLE, "unreachable")
        }
        Problem::Source
        | Problem::FirmwareRequired
        | Problem::FirmwareOlder {
            source: _,
            target: _,
        }
        | Problem::Unsupported => Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"),
    })?;
    let request = basis
        .request(visit.record(), state, services)
        .map_err(|_refused| Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"))?;
    let plan_id = request.plan.plan_id.clone();
    if visit.record().preview() != Some(plan_id.as_str()) {
        visit.record_mut().preview_ready(plan_id);
        visit.save().await.map_err(Failure::Broken)?;
        return Err(Failure::Refused(keys::WEB_PRESETS_APPLY_CHANGED, "changed"));
    }
    let phases = &request.plan.phases;
    let texts = phases
        .additive
        .iter()
        .chain(&phases.prune)
        .chain(&phases.management)
        .map(|line| {
            let number = line.source_index.saturating_add(1);
            (line.source_index, (number, redacted(line.expose_command())))
        })
        .collect::<BTreeMap<_, _>>();
    Ok(Starting::new(request, texts))
}

/// The preview again with `reason`, as 422 in the step.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn refusal(visit: &Visit<'_>, state: &WebState, reason: String) -> Answer {
    let panel = Panel::new(visit, state).await.refusing(reason);
    screen::refused(&panel).into()
}

/// The new WireGuard public keys of `report`, and the interfaces whose captured key was
/// copied.
fn wireguard(report: &ApplyReport) -> (Vec<(String, String)>, Vec<String>) {
    let keys = report
        .wireguard_public_keys
        .iter()
        .map(|key| (key.interface.clone(), key.public_key.clone()))
        .collect();
    let kept = report
        .warnings
        .iter()
        .filter_map(|warning| {
            let ApplyWarning::WireGuardPrivateKeyKept { interface } = warning else {
                return None;
            };
            Some(interface.clone())
        })
        .collect();
    (keys, kept)
}
