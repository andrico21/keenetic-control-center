//! `POST /ui/admin/notifications/token` and `.../token/clear`: the write-only bot token.
//!
//! The typed token moves into a `SecretString` before any other use, is sealed with the
//! master key and is never rendered, logged or audited; the audit log records only that
//! the credential changed or was cleared.

use axum::{Form, extract::State, response::Response};
use kcc_app::notify_store::{NotifyError, token::NotifySecrets};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{
    form::TokenForm,
    page::{changed, refused},
    view::Field,
};
use crate::{
    WebState,
    admin_shared::unavailable,
    authz::CurrentUser,
    errors,
    page_kit::{
        confirm::{Confirmation, Dialog, Resubmit, Words},
        context::fragment_shell,
        respond,
    },
};

/// Where the removal is confirmed.
const CLEAR: &str = "/ui/admin/notifications/token/clear";

/// `POST /ui/admin/notifications/token`: seals the pasted token; an empty or malformed
/// one is refused under the field.
// NOT cancel-safe: the token is sealed on a blocking thread that finishes even if the future is
// dropped, leaving the change unaudited and the notifier not reloaded.
pub(crate) async fn save_token(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<TokenForm>,
) -> Response {
    let (Some(admin), Some(fleet)) = (state.admin(), state.fleet()) else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let Some(token) = form.into_token() else {
        return refuse(&state, locale, keys::WEB_ADMIN_NOTIFY_ERROR_TOKEN_EMPTY).await;
    };
    let store = admin.state().clone();
    let key = fleet.workflow().backups().key().duplicate();
    match spawn_blocking(move || NotifySecrets::set_token(&store, &key, &token)).await {
        Ok(Ok(())) => {}
        Ok(Err(NotifyError::Invalid { field: _ })) => {
            return refuse(&state, locale, keys::WEB_ADMIN_NOTIFY_ERROR_TOKEN).await;
        }
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(locale)),
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    }
    changed(
        &state,
        &user,
        ("web.notify_token", json!({ "credential_changed": true })),
        keys::WEB_ADMIN_NOTIFY_TOKEN_SAVED,
    )
    .await
}

/// `GET /ui/admin/notifications/token/clear`: the confirmation.
// cancel-safe: it has no await point.
pub(crate) async fn clear_dialog(user: CurrentUser) -> Response {
    confirmation(user.locale()).show()
}

/// `POST /ui/admin/notifications/token/clear`: removes the sealed token once confirmed;
/// unconfirmed, it asks.
// NOT cancel-safe: the token file is removed on a blocking thread that finishes even if the future
// is dropped, leaving the change unaudited and the notifier not reloaded.
pub(crate) async fn clear_token(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(confirmation_form): Form<Confirmation>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let locale = user.locale();
    if !confirmation_form.confirmed() {
        return confirmation(locale).show();
    }
    let _changes = admin.lock().await;
    let store = admin.state().clone();
    match spawn_blocking(move || NotifySecrets::clear(&store)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(locale)),
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    }
    respond::close_dialog(
        changed(
            &state,
            &user,
            ("web.notify_token", json!({ "credential_cleared": true })),
            keys::WEB_ADMIN_NOTIFY_TOKEN_CLEARED,
        )
        .await,
    )
}

/// The region with `message` under the token field, as 422.
// cancel-safe: it only reads local state on a blocking thread.
async fn refuse(state: &WebState, locale: Locale, message: MessageKey) -> Response {
    refused(state, locale, |region| {
        region.refuse(Field::Token, tr(locale, message, None));
    })
    .await
}

/// The removal's confirmation in `locale`.
fn confirmation(locale: Locale) -> Dialog {
    let words = Words::new(
        tr(locale, keys::WEB_ADMIN_NOTIFY_TOKEN_CLEAR_TITLE, None),
        tr(locale, keys::WEB_ADMIN_NOTIFY_TOKEN_CLEAR_TEXT, None),
        tr(locale, keys::WEB_ADMIN_NOTIFY_TOKEN_CLEAR, None),
    );
    Dialog::new(
        locale,
        words,
        Resubmit::new(CLEAR.to_owned(), "#page-outcome"),
    )
}
