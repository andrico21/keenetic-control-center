//! How a change of the connections tab replies: the confirmation dialog before it, and
//! the region read again with a toast once it is done.

use axum::{http::StatusCode, response::Response};
use fluent_bundle::FluentArgs;
use kcc_i18n::bundle::{MessageKey, tr};

use super::{RegisterForm, region};
use crate::{
    WebState,
    admin_shared::{Change, done_toasts, record},
    authz::CurrentUser,
    errors,
    page_kit::{
        confirm::{Ask, Dialog, Resubmit, Words},
        context::fragment_shell,
        respond,
    },
};

/// The dialog asking for `ask` before the change: its `(title, args)`, `text`, and the
/// `(button, action)` that sends the change again.
pub(super) fn ask(
    user: &CurrentUser,
    (title, args): (MessageKey, &FluentArgs<'_>),
    text: MessageKey,
    (button, action): (MessageKey, String),
    ask: Ask,
) -> Response {
    let locale = user.locale();
    let words = Words::new(
        tr(locale, title, Some(args)),
        tr(locale, text, None),
        tr(locale, button, None),
    );
    Dialog::new(locale, words, Resubmit::new(action, "#page-outcome"))
        .with_text_key(text)
        .asking(ask)
        .show()
}

/// Audits `change` and answers with the region read again, out of band, and the `done`
/// toast; the dialog closes.
// NOT cancel-safe: the audit entry may be written after the future is dropped.
pub(super) async fn answer(
    state: &WebState,
    user: &CurrentUser,
    change: Change<'_>,
    done: MessageKey,
) -> Response {
    record(state, user, change).await;
    let toasts = done_toasts(user.locale(), done, None);
    match region(state, user.locale(), RegisterForm::default(), toasts).await {
        Ok(mut refreshed) => {
            refreshed.oob = true;
            respond::region(&refreshed, StatusCode::OK, true)
        }
        Err(error) => errors::internal(&*error, fragment_shell(user.locale())),
    }
}
