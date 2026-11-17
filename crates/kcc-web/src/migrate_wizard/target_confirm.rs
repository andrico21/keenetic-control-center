//! Step 2's Continue: the target must be usable, and a documentation-based firmware
//! tier acknowledged; the acknowledgement (and its absence) goes to the audit log.

use alloc::sync::Arc;

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;
use serde_json::json;

use super::{access::Visit, kinds::Step, record::Record, target::Panel};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
    wizard::{flow::Flow as _, screen, service::Wizards, services::Services},
};

/// The acknowledgement of the firmware tier.
#[derive(Debug, Default, Deserialize)]
pub(super) struct Confirm {
    /// `yes` when the documentation-based tier is acknowledged.
    #[serde(default)]
    acknowledge: Option<String>,
}

/// `POST /ui/migrate/{id}/target/continue`: moves on to the maps once the target can be
/// used and its documentation-based tier, if any, is acknowledged (audited).
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with its error (422).
pub(super) async fn confirm(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Confirm>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let Some(router) = visit.record().target().map(str::to_owned) else {
        return Ok(screen::moved(visit.record()));
    };
    if visit.record().step() != Step::Target {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let panel = Panel::new(&visit).await;
    let Some((needs_ack, unsupported)) = panel.tier() else {
        return Err(respond::unprocessable(&panel).into());
    };
    if unsupported {
        return Err(respond::unprocessable(&panel).into());
    }
    let acknowledged = form.acknowledge.as_deref() == Some("yes");
    if needs_ack && !acknowledged {
        let refused = panel.refusing_ack(tr(locale, keys::WEB_MIGRATE_ACK_REQUIRED, None));
        Audit::on_router("web.migrate_ack_documentation_tier", &router, id)
            .append(&state, &user, "missing")
            .await;
        return Err(respond::unprocessable(&refused).into());
    }
    visit.record_mut().confirm_target(needs_ack);
    if let Err(error) = visit.save().await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    if needs_ack {
        Audit::on_router("web.migrate_ack_documentation_tier", &router, id)
            .with_params(json!({ "acknowledged": true }))
            .append(&state, &user, "acknowledged")
            .await;
    }
    Ok(screen::moved(visit.record()))
}
