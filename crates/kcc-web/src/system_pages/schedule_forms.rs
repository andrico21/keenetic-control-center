//! The add-schedule dialog and its change.
//!
//! The router's CLI takes a schedule's name and description as one word each, so both are
//! checked here before anything is sent.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::schedules;
use kcc_i18n::{bundle::tr, keys};

use super::{
    schedules::Viewer,
    shared::{answer, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::Change,
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        request::shown_query,
        respond::{self, Answer},
    },
};

/// Adding a schedule, audited as `web.schedule_create`.
const CREATE: Operation = Operation::write(&schedules::DESCRIPTOR, "create", "web.schedule_create");

/// Longest name or description accepted, in characters.
const WORD_CHARS: usize = 64;

/// The add-schedule dialog.
#[derive(Template)]
#[template(path = "partials/system_schedule_dialog.html")]
struct ScheduleDialog {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The name as typed.
    name_value: String,
    /// Localized error under the name; empty when none.
    name_error: String,
    /// The description as typed.
    description_value: String,
    /// Localized error under the description; empty when none.
    description_error: String,
}

localized!(ScheduleDialog);

/// Whether `value` is one word the router's CLI takes: 1 to 64 Latin letters, digits,
/// dots, hyphens and underscores.
fn is_word(value: &str) -> bool {
    (1..=WORD_CHARS).contains(&value.chars().count())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
}

/// `GET /ui/r/{router}/system/schedules/new`: the add-schedule dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn new_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    Ok(errors::render(&ScheduleDialog {
        shell: fragment_shell(action.locale()),
        router,
        name_value: String::new(),
        name_error: String::new(),
        description_value: String::new(),
        description_error: String::new(),
    }))
}

/// `POST /ui/r/{router}/system/schedules`: adds a schedule, with its description when one
/// was typed.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let name = value(&pairs, "name").unwrap_or_default();
    let description = value(&pairs, "description").unwrap_or_default();
    let mut dialog = ScheduleDialog {
        shell: fragment_shell(locale),
        router: router.clone(),
        name_value: name.to_owned(),
        name_error: String::new(),
        description_value: description.to_owned(),
        description_error: String::new(),
    };
    let word_error = tr(locale, keys::WEB_SYSTEM_SCHEDULES_WORD_ERROR, None);
    if !is_word(name) {
        dialog.name_error.clone_from(&word_error);
    }
    if !description.is_empty() && !is_word(description) {
        dialog.description_error = word_error;
    }
    if !dialog.name_error.is_empty() || !dialog.description_error.is_empty() {
        action.abandon("validation_failed").await;
        return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
    }
    let domain = action.context().await?;
    let planned = if description.is_empty() {
        schedules::plan_create(&domain, name)
    } else {
        schedules::plan_description(&domain, name, description)
    }
    .and_then(|operation| schedules::change_request(&operation));
    let request = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            plan_failure(Family::Changes, locale, &error)
                .message()
                .clone_into(&mut dialog.name_error);
            return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
        }
    };
    let outcome = action.run(Risk::Write, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&domain)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, locale))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::is_word;

    #[test]
    fn names_and_descriptions_are_one_word() {
        assert!(is_word("night-shift_2"), "one word");
        assert!(!is_word("night shift") && !is_word(""), "spaces, empty");
        assert!(!is_word(&"a".repeat(65)), "too long");
    }
}
