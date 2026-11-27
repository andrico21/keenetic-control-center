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
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{
        action::Action,
        confirm::{Ask, Dialog, Resubmit, Words},
        context::fragment_shell,
        outcome::{Failure, Outcome, with_status},
        read_failure::ReadProblem,
        request::rendered,
        respond,
        respond::Changed,
        submit::{Form, Invalid},
    },
};

/// The confirmation of a removal: what goes and the button that removes it; the answer
/// lands in the page's outcome region.
pub(crate) struct ConfirmDialog(Dialog);

impl ConfirmDialog {
    /// The confirmation titled `title` (localized), explained by `text`, posting to
    /// `action`.
    pub(crate) fn new(locale: Locale, title: String, text: MessageKey, action: String) -> Self {
        let words = Words::new(
            title,
            tr(locale, text, None),
            tr(locale, keys::WEB_ROUTING_REMOVE, None),
        );
        Self(Dialog::new(locale, words, Resubmit::new(action, "#page-outcome")).asking(Ask::Button))
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        self.0.show()
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
#[template(ext = "html", source = "\n{{ changed }}")]
struct Answered {
    /// Locale carrier.
    shell: Shell,
    /// The kit's answer.
    changed: Changed,
}

localized!(GuardView, Answered);

/// The answer to a change: `outcome` in the page's outcome region, `refreshed` out of
/// band, the shared dialog closed.
pub(crate) fn answer(outcome: Outcome, refreshed: Option<Rendered>, locale: Locale) -> Response {
    guarded(outcome, None, refreshed, locale)
}

/// [`answer`] with the route-wipe guard's report in place of the outcome's notice, and the
/// unsaved badge when the restore left the router with unsaved changes.
pub(crate) fn guarded(
    outcome: Outcome,
    guard: Option<Guard>,
    refreshed: Option<Rendered>,
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

/// A form of these pages: values that failed their check are answered by the page's own
/// form, refusals and changes as these pages answer them ([`answer`]).
pub(crate) struct Replying<F>(F);

impl<F> Replying<F> {
    /// `form`, answering refusals and changes as these pages do.
    pub(crate) const fn new(form: F) -> Self {
        Self(form)
    }
}

impl<F: Form> Form for Replying<F> {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        self.0.answer_invalid(invalid, locale)
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        answer(Outcome::failed(failure), None, locale)
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<Rendered>,
        locale: Locale,
    ) -> Response {
        answer(outcome, refreshed, locale)
    }
}

/// The audited answer to a change refused before anything was sent: `failure` in the
/// page's outcome region.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn refused(action: Action<'_>, failure: Failure) -> Response {
    let locale = action.locale();
    action.abandon(failure.audit()).await;
    answer(Outcome::failed(failure), None, locale)
}

/// The failure of a change whose router could not be read first: `problem`, nothing sent.
pub(crate) fn unread(locale: Locale, problem: &ReadProblem) -> Failure {
    problem.failure(locale, "unreachable")
}

/// The failure of a change of something the router no longer has.
pub(crate) fn gone(locale: Locale) -> Failure {
    Failure::new(tr(locale, keys::WEB_ROUTING_GONE, None), "gone")
}
