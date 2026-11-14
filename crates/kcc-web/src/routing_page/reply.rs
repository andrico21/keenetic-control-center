//! How the routing, port forwarding and firewall pages answer.
//!
//! The plain confirmation of a removal, and the answer to a change with its outcome (or the
//! route-wipe guard's banner) and the view's region read back.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::guard::Guard;
use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Action,
        context::fragment_shell,
        outcome::{Failure, Outcome, with_status},
        respond,
    },
};

/// The confirmation of a removal: what goes and the button that removes it; the answer
/// lands in the page's outcome region (`partials/routing_confirm.html`).
#[derive(Template)]
#[template(path = "partials/routing_confirm.html")]
pub(crate) struct ConfirmDialog {
    /// Locale carrier.
    shell: Shell,
    /// The question naming the object.
    title: String,
    /// What the removal does.
    text: MessageKey,
    /// Where the confirming button posts.
    action: String,
}

localized!(ConfirmDialog);

impl ConfirmDialog {
    /// The confirmation titled `title` (localized), explained by `text`, posting to
    /// `action`.
    pub(crate) const fn new(
        locale: Locale,
        title: String,
        text: MessageKey,
        action: String,
    ) -> Self {
        Self {
            shell: fragment_shell(locale),
            title,
            text,
            action,
        }
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }
}

/// The answer to a change: its outcome or the route-wipe guard's banner, then the view's
/// region read back, out of band (`partials/routing_result.html`).
#[derive(Template)]
#[template(path = "partials/routing_result.html")]
struct ResultView {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
    /// What the route-wipe guard did, shown instead of the outcome's notice.
    guard: Option<Guard>,
    /// The region read back.
    refreshed: Option<String>,
}

localized!(ResultView);

/// The answer to a change: `outcome` in the page's outcome region, `refreshed` out of
/// band, the shared dialog closed.
pub(crate) fn answer(outcome: Outcome, refreshed: Option<String>, locale: Locale) -> Response {
    guarded(outcome, None, refreshed, locale)
}

/// [`answer`] with the route-wipe guard's banner in place of the outcome's notice.
pub(crate) fn guarded(
    outcome: Outcome,
    guard: Option<Guard>,
    refreshed: Option<String>,
    locale: Locale,
) -> Response {
    let status = outcome.status();
    let view = ResultView {
        shell: fragment_shell(locale),
        outcome,
        guard,
        refreshed,
    };
    respond::close_dialog(with_status(errors::render(&view), status))
}

/// The audited answer to a change whose router could not be read first: `message` in the
/// page's outcome region, nothing sent.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn unread(action: Action<'_>, message: MessageKey) -> Response {
    let locale = action.locale();
    action.abandon("unreachable").await;
    let failure = Failure::new(tr(locale, message, None), "unreachable");
    answer(Outcome::failed(failure), None, locale)
}

/// The audited answer to a change of something the router no longer has.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn gone(action: Action<'_>) -> Response {
    let locale = action.locale();
    action.abandon("gone").await;
    let failure = Failure::new(tr(locale, keys::WEB_ROUTING_GONE, None), "gone");
    answer(Outcome::failed(failure), None, locale)
}
