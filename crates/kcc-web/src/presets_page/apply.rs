//! Steps 6 to 8: Apply, Stop and Review the result.
//!
//! Apply asks first, then reserves the target (one apply per router at a time among the
//! presets' runs) and starts the apply; step 7 follows it live with Stop, and Review the
//! result opens step 8 once it ended.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use kcc_migrate::apply::ApplyOptions;
use serde_json::json;

use super::{
    access::Visit,
    launch::{Failure, launch},
    preview::{Panel, apply_permissions},
    record::Record,
    steps::Step,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record as Audit,
        confirm::{Confirmation, Dialog, Resubmit, Words},
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
    wizard::{flow::Flow as _, screen, screen::refused, service::Wizards, services::Services},
};

/// `POST /ui/presets/runs/{run}/apply`: asks first, then starts the apply.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403 without the permissions the apply
/// needs, and the preview with the reason (422) when it cannot start.
// NOT cancel-safe: see `launch`.
pub(super) async fn apply(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Preview {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let audit = Audit::on_router("web.preset_apply", &target, id.clone());
    let missing = errors::refusal::missing(&user, &target, &apply_permissions());
    if !missing.is_empty() {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::refusal::refused(locale, &missing, "#wizard-step").into());
    }
    let Some(jobs) = state.advanced().jobs().cloned() else {
        return Err(refusal(&visit, &state, keys::WEB_MIGRATE_APPLY_NO_JOBS).await);
    };
    if !form.confirmed() {
        let mut args = FluentArgs::new();
        args.set("router", target.clone());
        let minutes = ApplyOptions::default().safety_seconds.div_ceil(60);
        args.set("minutes", u32::try_from(minutes).unwrap_or(u32::MAX));
        let words = Words::new(
            tr(locale, keys::WEB_PRESETS_APPLY_CONFIRM_TITLE, Some(&args)),
            tr(locale, keys::WEB_PRESETS_APPLY_CONFIRM_TEXT, Some(&args)),
            tr(locale, keys::WEB_PRESETS_APPLY_BUTTON, None),
        );
        let resubmit = Resubmit::new(format!("/ui/presets/runs/{id}/apply"), "#wizard-step");
        return Ok(Dialog::new(locale, words, resubmit).show());
    }
    if !runs.claim(&target, &id) {
        audit.append(&state, &user, "busy").await;
        return Err(refusal(&visit, &state, keys::WEB_PRESETS_APPLY_BUSY).await);
    }
    match launch(&mut visit, &state, &jobs, &runs).await {
        Ok((job, commands)) => {
            audit
                .with_params(json!({ "job": job, "commands": commands }))
                .append(&state, &user, "started")
                .await;
            Ok(screen::moved(visit.record()))
        }
        Err(failure) => {
            runs.release(&target, &id);
            match failure {
                Failure::Refused(key, outcome) => {
                    audit.append(&state, &user, outcome).await;
                    Err(refusal(&visit, &state, key).await)
                }
                Failure::Broken(error) => {
                    Err(errors::internal(&error, fragment_shell(locale)).into())
                }
            }
        }
    }
}

/// The preview again with `key` as its reason, as 422 in the step.
// cancel-safe: reads only.
async fn refusal(visit: &Visit<'_>, state: &WebState, key: MessageKey) -> Answer {
    let locale = visit.services().user().locale();
    let panel = Panel::new(visit, state)
        .await
        .refusing(tr(locale, key, None));
    refused(&panel).into()
}
