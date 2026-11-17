//! The add-schedule dialog and its change.
//!
//! The router's CLI takes a schedule's name as one word, and this page holds the
//! description to one word as well, so both are checked here before anything is sent.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::schedules;
use kcc_i18n::{keys, locale::Locale};

use super::{schedules::Viewer, shared::value};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        form::{FormDialog, Input},
        request::{Params, shown_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// Adding a schedule, audited as `web.schedule_create`.
const CREATE: Operation = Operation::write(&schedules::DESCRIPTOR, "create", "web.schedule_create");

/// Longest name or description accepted, in characters.
const WORD_CHARS: usize = 64;

/// The add-schedule dialog on `router` in `locale`, showing the `name` and `description`
/// as typed; a change the domain could not plan shows under the name.
fn schedule_dialog(router: &str, locale: Locale, (name, description): (&str, &str)) -> FormDialog {
    let field = |field, label, value: &str| {
        Input::field(field, label, value.to_owned()).help(keys::WEB_SYSTEM_SCHEDULES_WORD_HELP)
    };
    FormDialog::new(
        locale,
        keys::WEB_SYSTEM_SCHEDULES_ADD_TITLE,
        format!("/ui/r/{router}/system/schedules"),
    )
    .ids("schedule")
    .submit(keys::WEB_SYSTEM_SCHEDULES_ADD)
    .refusing_at("name")
    .with_input(field("name", keys::WEB_SYSTEM_SCHEDULES_NAME, name))
    .with_input(field(
        "description",
        keys::WEB_SYSTEM_SCHEDULES_DESCRIPTION,
        description,
    ))
}

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
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn new_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    Ok(schedule_dialog(&router, action.locale(), ("", "")).show())
}

/// `POST /ui/r/{router}/system/schedules`: adds a schedule, with its description when one
/// was typed.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
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
    let dialog = schedule_dialog(&router, locale, (name, description));
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    let resubmit = Resubmit::new(format!("/ui/r/{router}/system/schedules"), "#page-outcome");
    Ok(
        Submission::new(action, &Params::default(), dialog, resubmit)
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
            .await,
    )
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
