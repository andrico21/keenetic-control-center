//! Step 2's submits: choosing the target, whose inventory is read (nothing is written),
//! and continuing once its documentation-based firmware tier is acknowledged.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;
use serde_json::json;

use super::{
    access::Visit,
    screen,
    steps::{Origin, Step},
    target::{Panel, problem_text},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    migrate_wizard::{access::Services, service::Wizards},
    overview::is_profile_id,
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
};

/// The router choice.
#[derive(Debug, Deserialize)]
pub(super) struct Choice {
    /// The target router.
    #[serde(default)]
    router: String,
}

/// `POST /ui/presets/runs/{run}/target`: checks the target, reads its inventory and
/// shows its warnings.
///
/// # Errors
///
/// Answers the refusal of the run, and the panel with its error (422): a router the user
/// may not migrate with is refused before any request to it.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn choose(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(choice): Form<Choice>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Target {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let router = choice.router.trim().to_owned();
    let copy_source = match visit.record().origin() {
        Origin::Copy => visit.record().source_router(),
        Origin::Preset { id: _, name: _ } => None,
    };
    let refused = if copy_source == Some(router.as_str()) {
        Some(keys::WEB_MIGRATE_TARGET_ERROR_SAME)
    } else if services.permits(&router).await {
        None
    } else {
        Some(keys::WEB_MIGRATE_TARGET_ERROR_ROUTER)
    };
    if let Some(message) = refused {
        let audit = if is_profile_id(&router) {
            Audit::on_router("web.preset_target", &router, id)
        } else {
            Audit::new("web.preset_target", id)
        };
        audit.append(&state, &user, "forbidden").await;
        let panel = Panel::refused(&visit, tr(locale, message, None), String::new()).await;
        return Err(respond::unprocessable(&panel).into());
    }
    visit.record_mut().choose_target(router.clone());
    visit.session().forget();
    let read = match visit.preset() {
        Ok(preset) => visit.inventory(&preset).await.map(drop),
        Err(problem) => Err(problem),
    };
    if let Err(problem) = read {
        let panel = Panel::refused(&visit, String::new(), problem_text(&problem, locale)).await;
        Audit::on_router("web.preset_target", &router, id)
            .append(&state, &user, "refused")
            .await;
        return Err(respond::unprocessable(&panel).into());
    }
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    Audit::on_router("web.preset_target", &router, id)
        .append(&state, &user, "chosen")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The acknowledgement of the firmware tier.
#[derive(Debug, Default, Deserialize)]
pub(super) struct Acknowledgement {
    /// `yes` when the documentation-based tier is acknowledged.
    #[serde(default)]
    acknowledge: Option<String>,
}

/// `POST /ui/presets/runs/{run}/target/continue`: moves on to the options once the target
/// can be used and its documentation-based tier, if any, is acknowledged (audited).
///
/// # Errors
///
/// Answers the refusal of the run, and the panel with its error (422).
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn confirm(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Acknowledgement>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    let Some(router) = visit.record().target().map(str::to_owned) else {
        return Ok(screen::moved(visit.record()));
    };
    if visit.record().step() != Step::Target {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let mut panel = Panel::new(&visit).await;
    let Some((needs_ack, unsupported)) = panel.tier() else {
        return Err(respond::unprocessable(&panel).into());
    };
    if unsupported {
        return Err(respond::unprocessable(&panel).into());
    }
    let acknowledged = form.acknowledge.as_deref() == Some("yes");
    let audit = Audit::on_router("web.preset_ack_documentation_tier", &router, id);
    if needs_ack && !acknowledged {
        panel.require_ack(locale);
        audit.append(&state, &user, "missing").await;
        return Err(respond::unprocessable(&panel).into());
    }
    visit.record_mut().confirm_target(needs_ack);
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    if needs_ack {
        audit
            .with_params(json!({ "acknowledged": true }))
            .append(&state, &user, "acknowledged")
            .await;
    }
    Ok(screen::moved(visit.record()))
}
