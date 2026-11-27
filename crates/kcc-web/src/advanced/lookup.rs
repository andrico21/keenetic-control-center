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
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Target, fragment_shell},
        facts::{FactsError, RouterFacts},
        family::Family,
        read_failure::ReadProblem,
    },
};

/// Longest search query or command path read from a request.
const MAX_INPUT: usize = 200;

/// A one-line notice fragment, with kcc's technical detail of a failed read.
#[derive(Template)]
#[template(
    ext = "html",
    source = "{%- import \"partials/kit_macros.html\" as kit -%}<p class=\"notice\" data-tone=\"{{ tone }}\">{{ t_read(message) }}</p>{%- if let Some(detail) = message.detail() %}{{ kit::details(detail) }}{%- endif %}"
)]
struct Notice {
    /// Locale carrier.
    shell: Shell,
    /// Notice tone.
    tone: &'static str,
    /// The message.
    message: ReadProblem,
}

localized!(Notice);

/// A router the user may read and its catalog facts, or the fragment answering instead.
///
/// # Errors
///
/// Returns the status or notice to answer with.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
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
        .map_err(|error| Box::new(unread(user.locale(), problem(&error))))?;
    Ok((target, facts))
}

/// A notice fragment.
pub(crate) fn notice(locale: Locale, tone: &'static str, message: MessageKey) -> Response {
    errors::render(&Notice {
        shell: fragment_shell(locale),
        tone,
        message: message.into(),
    })
}

/// An error notice fragment saying why a router read failed.
pub(crate) fn unread(locale: Locale, problem: ReadProblem) -> Response {
    errors::render(&Notice {
        shell: fragment_shell(locale),
        tone: "error",
        message: problem,
    })
}

/// The message explaining why no catalog is available.
pub(crate) fn problem(error: &FactsError) -> ReadProblem {
    error.problem(Family::Commands)
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
