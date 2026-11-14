//! Deleting a preset: `GET /ui/presets/{id}/delete` asks for its name, `POST` deletes it
//! once the name is typed (`Migrate` on its source router, audited either way).

use axum::{
    Form,
    extract::{Path, State, rejection::FormRejection},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::presets::{model::Preset, store::PresetError};

use super::{list::may_change, saved};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page_kit::{
        audit::Record as Audit,
        confirm::{Dialog, TypedNameForm},
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
    wizard::services::Services,
};

/// `GET /ui/presets/{id}/delete`: the typed-name confirmation.
///
/// # Errors
///
/// Answers 404 for a preset the user does not see and 403 without `Migrate` on its
/// source router.
// cancel-safe: reads only.
pub(super) async fn dialog(
    State(state): State<WebState>,
    Path(id): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let preset = deletable(services, &id)?;
    Ok(errors::render(&confirmation(user.locale(), &preset)))
}

/// `POST /ui/presets/{id}/delete`: deletes the preset once its name is typed.
///
/// # Errors
///
/// Answers 404, the audited 403 (before the form is read), and the dialog with its error
/// (422).
// NOT cancel-safe: the preset is deleted before the audit append.
pub(super) async fn delete(
    State(state): State<WebState>,
    Path(id): Path<String>,
    user: CurrentUser,
    form: Result<Form<TypedNameForm>, FormRejection>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let locale = user.locale();
    let preset = match deletable(services, &id) {
        Ok(found) => found,
        Err(answer) => {
            Audit::new("web.preset_delete", id)
                .append(&state, &user, "refused")
                .await;
            return Err(answer);
        }
    };
    let audit = preset.source.router_id.as_deref().map_or_else(
        || Audit::new("web.preset_delete", id.clone()),
        |router| Audit::on_router("web.preset_delete", router, id.clone()),
    );
    let typed = form
        .ok()
        .filter(|Form(sent)| sent.name() == preset.name && sent.confirmed());
    if typed.is_none() {
        let mut asked = confirmation(locale, &preset);
        asked.set_error(tr(locale, keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return Err(respond::unprocessable(&asked).into());
    }
    match saved::store(services.fleet()).delete(user.role(), &id) {
        Ok(()) => {
            audit.append(&state, &user, "deleted").await;
            Ok(respond::open("/ui/presets"))
        }
        Err(PresetError::Forbidden) => {
            audit.append(&state, &user, "forbidden").await;
            Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into())
        }
        Err(PresetError::NotFound) => Err(StatusCode::NOT_FOUND.into_response().into()),
        Err(error) => Err(errors::internal(&error, fragment_shell(locale)).into()),
    }
}

/// The preset `id` when the user of `services` sees it and may delete it.
///
/// # Errors
///
/// Answers 404 or the localized 403.
fn deletable(services: Services<'_>, id: &str) -> Result<Preset, Answer> {
    let user = services.user();
    let presets = saved::store(services.fleet())
        .list(user.role())
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    let preset = presets
        .into_iter()
        .find(|preset| preset.id == id)
        .ok_or_else(|| Answer::from(StatusCode::NOT_FOUND.into_response()))?;
    if may_change(services, &preset) {
        Ok(preset)
    } else {
        Err(errors::response(Kind::Forbidden, fragment_shell(user.locale())).into())
    }
}

/// The confirmation of deleting `preset`.
fn confirmation(locale: Locale, preset: &Preset) -> Dialog {
    Dialog::typed_name(
        locale,
        format!("/ui/presets/{}/delete", preset.id),
        &preset.name,
        (
            keys::WEB_PRESETS_DELETE_TITLE,
            keys::WEB_PRESETS_DELETE_TEXT,
        ),
    )
}
