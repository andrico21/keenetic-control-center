//! Step 6 to 7 of every wizard: Apply asks first, then reserves the target (one apply per
//! router at a time among the wizard's runs) and starts the apply.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::apply::ApplyOptions;
use serde_json::json;

use super::{
    applying::{Applying, Failure},
    launch, screen,
    service::Wizards,
    services::Services,
    visit::Visit,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page_kit::{
        audit::Record as Audit,
        confirm::{Confirmation, Dialog, Resubmit, Words},
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
};

/// `POST {PREFIX}/{id}/apply`: asks first, then starts the apply.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403 without the permissions the apply
/// needs, the preview with the reason (422) when it cannot start, and an audited
/// internal error when the run's files or the job cannot be used.
// NOT cancel-safe: see `launch::start`.
pub(crate) async fn apply<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    user: CurrentUser,
    Form(form): Form<Confirmation>,
) -> Result<Response, Answer>
where
    F: Applying,
{
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != F::PREVIEW {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let audit = Audit::on_router(F::APPLY_AUDIT, &target, id.clone());
    let missing = errors::refusal::missing(&user, &target, &visit.record().apply_permissions());
    if !missing.is_empty() {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::refusal::refused(locale, &missing, "#wizard-step").into());
    }
    let Some(jobs) = state.advanced().jobs().cloned() else {
        let reason = tr(locale, keys::WEB_MIGRATE_APPLY_NO_JOBS, None);
        return Err(F::refusal(&visit, &state, reason).await);
    };
    if !form.confirmed() {
        return Ok(ask::<F>(locale, &id, &state.router_name(&target)));
    }
    if wizards.held_by_other(&target, &id) {
        audit.append(&state, &user, "busy").await;
        return Err(F::refusal(&visit, &state, tr(locale, F::BUSY, None)).await);
    }
    match launch::start(&mut visit, &state, (&jobs, &wizards)).await {
        Ok((job, commands)) => {
            audit
                .with_params(json!({ "job": job, "commands": commands }))
                .append(&state, &user, "started")
                .await;
            Ok(screen::moved(visit.record()))
        }
        Err(Failure::Refused(key, outcome)) => {
            audit.append(&state, &user, outcome).await;
            Err(F::refusal(&visit, &state, tr(locale, key, None)).await)
        }
        Err(Failure::Broken(error)) => {
            audit.append(&state, &user, "failed").await;
            Err(errors::internal(&error, fragment_shell(locale)).into())
        }
        Err(Failure::NotStarted(error)) => {
            audit.append(&state, &user, "failed").await;
            Err(errors::internal(&error, fragment_shell(locale)).into())
        }
        Err(Failure::Unowned) => {
            tracing::warn!("apply refused: its request has no server owner");
            audit.append(&state, &user, "failed").await;
            Err(errors::response(Kind::Internal, fragment_shell(locale)).into())
        }
    }
}

/// The dialog asking before the apply of run `id` to the router people read as `named`
/// starts.
fn ask<F>(locale: Locale, id: &str, named: &str) -> Response
where
    F: Applying,
{
    let mut args = FluentArgs::new();
    args.set("router", named.to_owned());
    let minutes = ApplyOptions::default().safety_seconds.div_ceil(60);
    args.set("minutes", u32::try_from(minutes).unwrap_or(u32::MAX));
    let (title, text, button) = F::CONFIRM;
    let words = Words::new(
        tr(locale, title, Some(&args)),
        tr(locale, text, Some(&args)),
        tr(locale, button, None),
    );
    let resubmit = Resubmit::new(format!("{}/apply", screen::href::<F>(id)), "#wizard-step");
    Dialog::new(locale, words, resubmit).show()
}
