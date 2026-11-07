//! Step 6 to 7: Apply asks first, then reserves the target (one apply per router at a
//! time) and starts the apply.

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
    locale::Locale,
};
use kcc_migrate::apply::ApplyOptions;
use serde_json::json;

use super::{
    access::{Services, Visit},
    confirm::{Confirm, Dialog, Words, refused},
    kinds::Step,
    launch::{Failure, launch},
    preview::{APPLY, Panel},
    screen,
    service::Wizards,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        gate::allowed,
        respond::Answer,
    },
};

/// `POST /ui/migrate/{id}/apply`: asks first, then starts the apply.
///
/// # Errors
///
/// Answers the refusal of the migration, the audited 403 without the permissions the
/// apply needs, and the preview with the reason (422) when it cannot start.
pub(super) async fn apply(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Confirm>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Preview {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let audit = Audit::on_router("web.migrate_apply", &target, id.clone());
    if !allowed(&user, &target, &APPLY) {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    }
    let Some(jobs) = state.advanced().jobs().cloned() else {
        return Err(refusal(&visit, keys::WEB_MIGRATE_APPLY_NO_JOBS).await);
    };
    if !form.confirmed() {
        return Ok(ask(locale, &id, &target));
    }
    if !wizards.claim(&target, &id) {
        audit.append(&state, &user, "busy").await;
        return Err(refusal(&visit, keys::WEB_MIGRATE_APPLY_BUSY).await);
    }
    match launch(&mut visit, &state, &jobs, &wizards).await {
        Ok((job, commands)) => {
            audit
                .with_params(json!({ "job": job, "commands": commands }))
                .append(&state, &user, "started")
                .await;
            Ok(screen::moved(visit.record()))
        }
        Err(failure) => {
            wizards.release(&target, &id);
            match failure {
                Failure::Refused(key, outcome) => {
                    audit.append(&state, &user, outcome).await;
                    Err(refusal(&visit, key).await)
                }
                Failure::Broken(error) => {
                    Err(errors::internal(&error, fragment_shell(locale)).into())
                }
            }
        }
    }
}

/// The dialog asking before the apply of migration `id` to `target` starts.
fn ask(locale: Locale, id: &str, target: &str) -> Response {
    let mut args = FluentArgs::new();
    args.set("router", target.to_owned());
    let minutes = ApplyOptions::default().safety_seconds.div_ceil(60);
    args.set("minutes", u32::try_from(minutes).unwrap_or(u32::MAX));
    let words = Words::new(
        tr(locale, keys::WEB_MIGRATE_APPLY_CONFIRM_TITLE, Some(&args)),
        tr(locale, keys::WEB_MIGRATE_APPLY_CONFIRM_TEXT, Some(&args)),
        tr(locale, keys::WEB_MIGRATE_APPLY, None),
    );
    Dialog::new(locale, words, format!("/ui/migrate/{id}/apply")).show()
}

/// The preview again with `key` as its reason, as 422 in the step.
// cancel-safe: reads only.
async fn refusal(visit: &Visit<'_>, key: MessageKey) -> Answer {
    let locale = visit.services().user().locale();
    let panel = Panel::new(visit).await.refusing(tr(locale, key, None));
    refused(&panel).into()
}
