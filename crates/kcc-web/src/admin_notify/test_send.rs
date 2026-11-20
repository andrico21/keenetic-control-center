//! `POST /ui/admin/notifications/test`: one test message to a configured chat through the
//! running notifier. The page shows "sent" or the failure's class, never the Bot API's
//! own words.

use core::time::Duration;

use axum::{Form, extract::State, response::Response};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use serde_json::json;
use tokio::time::timeout;

use super::{
    NotifyTestError,
    form::TestForm,
    page::{refused, region},
    store::seen,
    view::Field,
};
use crate::{
    WebState,
    admin_shared::unavailable,
    authz::CurrentUser,
    errors,
    page_kit::{audit::Record, context::fragment_shell},
};

/// Longest a test message may take before it counts as unreachable; below the request
/// time limit, so the outcome is still shown and audited.
const TEST_WAIT: Duration = Duration::from_secs(20);

/// `POST /ui/admin/notifications/test`: sends a test message to the chosen chat and shows
/// how it went; the audit entry names the chat's label and, on failure, the class.
// NOT cancel-safe: the notifier may send after the future is dropped, and the audit entry may be
// written late or not at all.
pub(crate) async fn send_test(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<TestForm>,
) -> Response {
    if state.admin().is_none() {
        return unavailable(None);
    }
    let locale = user.locale();
    let seen = match seen(&state).await {
        Ok(seen) => seen,
        Err(error) => return errors::internal(&*error, fragment_shell(locale)),
    };
    let Some(chat) = seen
        .settings()
        .chats
        .as_slice()
        .iter()
        .find(|chat| chat.id.as_str() == form.chat())
    else {
        return refused(&state, locale, |region| {
            region.refuse(
                Field::TestChat,
                tr(locale, keys::WEB_ADMIN_NOTIFY_ERROR_TEST_CHAT, None),
            );
        })
        .await;
    };
    let label = chat.label.as_str().to_owned();
    let (tone, message, failure) = match state.notify() {
        None => (
            "warning",
            keys::WEB_ADMIN_NOTIFY_TEST_NOT_RUNNING,
            Some("not_running"),
        ),
        Some(control) => {
            let sent = timeout(TEST_WAIT, control.send_test(chat.id.as_str()))
                .await
                .unwrap_or(Err(NotifyTestError::Unreachable));
            match sent {
                Ok(()) => ("success", keys::WEB_ADMIN_NOTIFY_TEST_SENT, None),
                Err(class) => ("error", words(class), Some(class.code())),
            }
        }
    };
    let (outcome, params) = failure.map_or_else(
        || ("success", json!({ "label": label })),
        |code| ("failed", json!({ "label": label, "failure": code })),
    );
    Record::new("web.notify_test", "telegram".to_owned())
        .with_params(params)
        .append(&state, &user, outcome)
        .await;
    let mut shown = region(&state, locale, &seen);
    shown.select_test_chat(form.chat());
    shown.show_test(tone, tr(locale, message, None));
    errors::render(&shown)
}

/// The words the page shows for the failure `class`.
const fn words(class: NotifyTestError) -> MessageKey {
    match class {
        NotifyTestError::NoToken => keys::WEB_ADMIN_NOTIFY_TEST_NO_TOKEN,
        NotifyTestError::TokenRejected => keys::WEB_ADMIN_NOTIFY_TEST_TOKEN_REJECTED,
        NotifyTestError::ChatRefused => keys::WEB_ADMIN_NOTIFY_TEST_CHAT_REFUSED,
        NotifyTestError::RateLimited => keys::WEB_ADMIN_NOTIFY_TEST_RATE_LIMITED,
        NotifyTestError::Unreachable => keys::WEB_ADMIN_NOTIFY_TEST_UNREACHABLE,
        NotifyTestError::Rejected => keys::WEB_ADMIN_NOTIFY_TEST_REJECTED,
    }
}
