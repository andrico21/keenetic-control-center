//! How the routing, port forwarding and firewall pages answer.
//!
//! The plain confirmation of a removal, and the answer to a change with its outcome (or the
//! route-wipe guard's report) and the view's region read back.

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
        request::rendered,
        respond,
        respond::Changed,
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

/// The route-wipe guard's report (`partials/routing_guard.html`).
#[derive(Template)]
#[template(path = "partials/routing_guard.html")]
struct GuardView {
    /// Locale carrier.
    shell: Shell,
    /// What the guard did.
    banner: Guard,
}

/// The answer of these pages: the kit's answer to a change, after a blank line.
#[derive(Template)]
#[template(ext = "html", source = "\n{{ changed|safe }}")]
struct Answered {
    /// Locale carrier.
    shell: Shell,
    /// The kit's answer.
    changed: Changed,
}

localized!(GuardView, Answered);

/// The answer to a change: `outcome` in the page's outcome region, `refreshed` out of
/// band, the shared dialog closed.
pub(crate) fn answer(outcome: Outcome, refreshed: Option<String>, locale: Locale) -> Response {
    guarded(outcome, None, refreshed, locale)
}

/// [`answer`] with the route-wipe guard's report in place of the outcome's notice, and the
/// unsaved badge when the restore left the router with unsaved changes.
pub(crate) fn guarded(
    outcome: Outcome,
    guard: Option<Guard>,
    refreshed: Option<String>,
    locale: Locale,
) -> Response {
    let changed = match guard {
        Some(banner) => {
            let shown = outcome.with_unsaved(banner.unsaved());
            let view = Changed::new(shown, refreshed, None, locale);
            let report = rendered(&GuardView {
                shell: fragment_shell(locale),
                banner,
            });
            match report {
                Some(text) => view.with_report(text),
                None => view,
            }
        }
        None => Changed::new(outcome, refreshed, None, locale),
    };
    let status = changed.status();
    let view = Answered {
        shell: fragment_shell(locale),
        changed,
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
