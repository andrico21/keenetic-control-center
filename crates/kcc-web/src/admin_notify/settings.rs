//! `POST /ui/admin/notifications`: whether to send, the language, the client-detail
//! switch and the events.

use axum::{Form, extract::State, response::Response};
use kcc_app::notify_store::NotifySettings;
use kcc_i18n::keys;

use super::{
    form::SettingsForm,
    page::{changed, refused},
    store::{blocking, store},
};
use crate::{
    WebState, admin_shared::unavailable, authz::CurrentUser, errors,
    page_kit::context::fragment_shell,
};

/// `POST /ui/admin/notifications`: stores the settings form; the chats stay as they are.
// NOT cancel-safe: the settings are written on a blocking thread that finishes even if the future
// is dropped, leaving the change unaudited and the notifier not reloaded.
pub(crate) async fn save(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let form = match SettingsForm::parse(&pairs) {
        Ok(form) => form,
        Err(refusal) => {
            return refused(&state, locale, |region| refusal.show(region, locale)).await;
        }
    };
    let stored = match store(&state) {
        Ok(stored) => stored,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let params = form.audit();
    let written =
        blocking(move || stored.update(|settings: &mut NotifySettings| form.apply(settings))).await;
    if let Err(error) = written {
        return errors::internal(&*error, fragment_shell(locale));
    }
    changed(
        &state,
        &user,
        ("web.notify_settings", params),
        keys::WEB_ADMIN_NOTIFY_SETTINGS_SAVED,
    )
    .await
}
