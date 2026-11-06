//! Lookups shared by the advanced handlers: the router and its catalog facts for a
//! fragment, and the small notices answering instead.

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize, Shell},
    page_kit::{
        context::{self, Target, fragment_shell},
        facts::{FactsError, RouterFacts},
        family::Family,
    },
};

/// Longest search query or command path read from a request.
const MAX_INPUT: usize = 200;

/// A one-line notice fragment.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<p class=\"notice\" data-tone=\"{{ tone }}\">{{ t(*message) }}</p>"
)]
struct Notice {
    /// Locale carrier.
    shell: Shell,
    /// Notice tone.
    tone: &'static str,
    /// The message.
    message: MessageKey,
}

impl Localize for Notice {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// A router the user may read and its catalog facts, or the fragment answering instead.
///
/// # Errors
///
/// Returns the status or notice to answer with.
// cancel-safe: reads only.
pub(crate) async fn facts_for<'state>(
    state: &'state WebState,
    user: &CurrentUser,
    router: &'state str,
) -> Result<(Target<'state>, RouterFacts), Box<Response>> {
    let target = context::target(state, user, router)
        .await
        .map_err(|refusal| Box::new(refusal.status()))?;
    let facts = target
        .facts(state)
        .await
        .map_err(|error| Box::new(notice(user.locale(), "error", problem(error))))?;
    Ok((target, facts))
}

/// A notice fragment.
pub(crate) fn notice(locale: Locale, tone: &'static str, message: MessageKey) -> Response {
    errors::render(&Notice {
        shell: fragment_shell(locale),
        tone,
        message,
    })
}

/// The message explaining why no catalog is available.
pub(crate) const fn problem(error: FactsError) -> MessageKey {
    error.message(Family::Commands)
}

/// `text` trimmed and cut to [`MAX_INPUT`] bytes at a character boundary.
pub(crate) fn clip(text: &str) -> &str {
    let trimmed = text.trim();
    let mut end = trimmed.len().min(MAX_INPUT);
    while !trimmed.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    trimmed.get(..end).unwrap_or_default()
}

/// The localized catalog line of `facts`.
pub(crate) fn catalog_note(facts: &RouterFacts, locale: Locale) -> String {
    let mut args = FluentArgs::new();
    args.set("version", facts.catalog().version().as_str());
    match facts.catalog_model() {
        Some(model) => {
            args.set("model", model.to_owned());
            tr(locale, keys::WEB_EXPLORER_CATALOG, Some(&args))
        }
        None => tr(locale, keys::WEB_EXPLORER_CATALOG_UNION, Some(&args)),
    }
}
