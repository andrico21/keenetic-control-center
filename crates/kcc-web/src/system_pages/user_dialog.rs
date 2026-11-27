//! The router-account dialog: add an account with its service tags, or change the tags
//! of one.
//!
//! The dialog shows the tags the router's catalog offers as checkboxes, explains the
//! fail-safe timer, and its Apply confirms the management change. The submitted name and
//! tags are checked here before anything is sent. Adding an account also offers its
//! password in two write-only fields, which never show a value.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    shared::value,
    user_forms::{CREATE, SET_TAG, find},
    users::{Account, offered_tags},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    page_kit::{
        confirm::FAIL_SAFE_MINUTES,
        form::{Choice, FormDialog, Input},
        request::missing,
        respond::Answer,
    },
};

/// Longest account name accepted, in characters.
const NAME_CHARS: usize = 32;

/// The add and tag dialog, built on the kit's form engine when it is shown.
pub(crate) struct UserDialog {
    /// The viewer's locale.
    locale: Locale,
    /// Localized title.
    title: String,
    /// Where the form posts.
    post_to: String,
    /// The account whose tags change; `None` while adding one.
    fixed_name: Option<String>,
    /// The name as typed.
    name_value: String,
    /// The tags the catalog offers and whether each is checked.
    choices: Vec<(String, bool)>,
    /// The submit button.
    submit: MessageKey,
}

impl UserDialog {
    /// The dialog with `offered` tags unchecked, its title and target still to set.
    pub(crate) fn base(locale: Locale, offered: &[String]) -> Self {
        Self {
            locale,
            title: String::new(),
            post_to: String::new(),
            fixed_name: None,
            name_value: String::new(),
            choices: offered.iter().map(|tag| (tag.clone(), false)).collect(),
            submit: keys::WEB_SYSTEM_USERS_ADD,
        }
    }

    /// The dialog adding an account to `router`.
    pub(crate) fn adding(self, router: &str) -> Self {
        Self {
            title: tr(self.locale, keys::WEB_SYSTEM_USERS_ADD_TITLE, None),
            post_to: format!("/ui/r/{router}/system/users"),
            ..self
        }
    }

    /// The dialog changing the tags of `account` on `router`, its tags checked.
    pub(crate) fn tagging(self, router: &str, account: &Account) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", account.name().to_owned());
        let current: Vec<&str> = account.tags().iter().map(String::as_str).collect();
        Self {
            title: tr(self.locale, keys::WEB_SYSTEM_USERS_TAGS_TITLE, Some(&args)),
            post_to: format!("/ui/r/{router}/system/users/tags"),
            fixed_name: Some(account.name().to_owned()),
            submit: keys::COMMON_APPLY,
            ..self
        }
        .checking(&current)
    }

    /// Checks exactly the `checked` tags.
    pub(crate) fn checking(mut self, checked: &[&str]) -> Self {
        for (tag, on) in &mut self.choices {
            *on = checked.contains(&tag.as_str());
        }
        self
    }

    /// Shows the name as typed.
    pub(crate) fn naming(mut self, name: &str) -> Self {
        name.clone_into(&mut self.name_value);
        self
    }

    /// The dialog's form: the confirmation, the name, the tags, a new account's password
    /// in two write-only fields and the fail-safe note.
    fn form(self) -> FormDialog {
        let mut args = FluentArgs::new();
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        let fail_safe = tr(self.locale, keys::WEB_SYSTEM_USERS_FAIL_SAFE, Some(&args));
        let dialog = FormDialog::titled(self.locale, self.title, self.post_to)
            .ids("user")
            .submit(self.submit)
            .with_input(Input::hidden("confirm", "yes".to_owned()));
        let named = match &self.fixed_name {
            Some(fixed) => dialog.with_input(Input::hidden("name", fixed.clone())),
            None => dialog.with_input(
                Input::field("name", keys::WEB_SYSTEM_USERS_NAME, self.name_value)
                    .help(keys::WEB_SYSTEM_USERS_NAME_HELP),
            ),
        };
        let tags = self
            .choices
            .iter()
            .map(|(tag, on)| Choice::plain(tag).checked(*on))
            .collect();
        let tagged = named.with_input(
            Input::text("tag", keys::WEB_SYSTEM_USERS_TAGS)
                .checks(tags)
                .id("user-tags")
                .mono(),
        );
        let secured = if self.fixed_name.is_none() {
            tagged
                .with_input(
                    Input::secret("secret", keys::WEB_SECRET_PASSWORD)
                        .id("user-password")
                        .help(keys::WEB_SECRET_ADD_HELP),
                )
                .with_input(
                    Input::secret("secret_again", keys::WEB_SECRET_REPEAT)
                        .id("user-password-again"),
                )
        } else {
            tagged
        };
        secured.closing(fail_safe)
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(self) -> Response {
        self.form().show()
    }

    /// The dialog with `message` under `field`, as 422 in the shared dialog.
    pub(crate) fn refused(self, field: Field, message: String) -> Answer {
        let name = match field {
            Field::Name => "name",
            Field::Tags => "tag",
            Field::Password => "secret_again",
        };
        self.form().with_error(name, message).invalid().into()
    }
}

/// The field a refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    /// The account name.
    Name,
    /// The tags.
    Tags,
    /// The new account's password and its repetition.
    Password,
}

/// `GET /ui/r/{router}/system/users/new`: the add dialog.
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
    let domain = action.context().await?;
    let dialog = UserDialog::base(action.locale(), &offered_tags(&domain.catalog)).adding(&router);
    Ok(dialog.show())
}

/// `GET /ui/r/{router}/system/users/tags?name=`: the tag dialog of one account.
///
/// # Errors
///
/// Answers 404 for an unknown account, the failure when the router cannot be read, and
/// what the kit answers when the router or the permission is missing.
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn tags_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = SET_TAG.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let name = value(&query, "name").unwrap_or_default();
    let account = find(&domain, name)
        .await
        .map_err(|problem| unusable(action.locale(), &problem))?
        .ok_or_else(missing)?;
    let offered = offered_tags(&domain.catalog);
    let dialog = UserDialog::base(action.locale(), &offered).tagging(&router, &account);
    Ok(dialog.show())
}

/// The submitted `name` and `tags`, checked against the `offered` tags.
///
/// # Errors
///
/// Returns the refused field and the message saying what a valid value looks like.
pub(crate) fn check(
    name: &str,
    tags: &[&str],
    offered: &[String],
) -> Result<(), (Field, MessageKey)> {
    let name_valid = (1..=NAME_CHARS).contains(&name.chars().count())
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character));
    if !name_valid {
        return Err((Field::Name, keys::WEB_SYSTEM_USERS_NAME_ERROR));
    }
    if tags
        .iter()
        .all(|tag| offered.iter().any(|known| known == tag))
    {
        Ok(())
    } else {
        Err((Field::Tags, keys::WEB_SYSTEM_USERS_TAGS_ERROR))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::keys;

    use super::{Field, check};

    #[test]
    fn names_and_tags_are_checked_before_anything_is_sent() {
        let offered = ["cli".to_owned(), "http".to_owned()];
        assert_eq!(check("lab-1", &["cli"], &offered), Ok(()), "valid");
        for bad in ["", "-lab", "lab user", "lab;x", &"a".repeat(33)] {
            assert_eq!(
                check(bad, &[], &offered),
                Err((Field::Name, keys::WEB_SYSTEM_USERS_NAME_ERROR)),
                "{bad}"
            );
        }
        assert_eq!(
            check("lab", &["root"], &offered),
            Err((Field::Tags, keys::WEB_SYSTEM_USERS_TAGS_ERROR)),
            "only offered tags"
        );
    }
}
