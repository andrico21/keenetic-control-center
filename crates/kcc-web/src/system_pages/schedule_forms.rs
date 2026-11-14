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
use kcc_domain::schedules;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{schedules::Viewer, shared::value};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::Change,
        context::fragment_shell,
        outcome::Failure,
        request::{Params, shown_query},
        respond::{self, Answer},
        submit::{self, Invalid, Planned, Submission},
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
    let dialog = ScheduleDialog {
        shell: fragment_shell(locale),
        router: router.clone(),
        name_value: name.to_owned(),
        name_error: String::new(),
        description_value: description.to_owned(),
        description_error: String::new(),
    };
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &Params::default(), dialog)
        .submit(
            |_params| {
                let mut invalid = Vec::new();
                if !is_word(name) {
                    invalid.push(("name", keys::WEB_SYSTEM_SCHEDULES_WORD_ERROR));
                }
                if !description.is_empty() && !is_word(description) {
                    invalid.push(("description", keys::WEB_SYSTEM_SCHEDULES_WORD_ERROR));
                }
                if invalid.is_empty() {
                    Ok(())
                } else {
                    Err(Invalid::from(invalid))
                }
            },
            async |(), domain| {
                let operation = if description.is_empty() {
                    schedules::plan_create(domain, name)
                } else {
                    schedules::plan_description(domain, name, description)
                }?;
                let request = schedules::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| viewer.refreshed(domain).await,
        )
        .await)
}

/// The add-schedule dialog answers values that failed their check, and a change the
/// domain could not plan, under the field they concern.
impl submit::Form for ScheduleDialog {
    fn answer_invalid(mut self, invalid: Invalid, locale: Locale) -> Response {
        for (field, rule) in invalid.into_findings() {
            let error = tr(locale, rule, None);
            if field == "description" {
                self.description_error = error;
            } else {
                self.name_error = error;
            }
        }
        respond::in_dialog(respond::unprocessable(&self))
    }

    fn answer_refused(mut self, failure: Failure, _locale: Locale) -> Response {
        failure.message().clone_into(&mut self.name_error);
        respond::in_dialog(respond::unprocessable(&self))
    }
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
