//! The connection-policy dialogs: Add policy, Description and Add interface, and the
//! one-word description rule they share.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    net_change::Params,
    net_form::{Choice, FormDialog, Input},
    system_pages::shared::with_query,
};

/// Longest description, in characters.
const WORD_CHARS: usize = 64;

/// An optional one-word description: empty is none.
///
/// # Errors
///
/// Returns the rule a description with spaces, quotes or more than 64 characters breaks.
pub(crate) fn word(typed: &str) -> Result<Option<String>, MessageKey> {
    let text = typed.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let printable = text
        .chars()
        .all(|character| !character.is_whitespace() && !character.is_control())
        && !text.contains(['"', '\'', '\\']);
    if printable && text.chars().count() <= WORD_CHARS {
        Ok(Some(text.to_owned()))
    } else {
        Err(keys::WEB_ROUTING_ERROR_WORD)
    }
}

/// The Add policy dialog on `router` with `values`.
pub(crate) fn create_form(locale: Locale, router: &str, values: &Params) -> FormDialog {
    let title = tr(locale, keys::WEB_ROUTING_POLICY_ADD_TITLE, None);
    FormDialog::new(locale, title, format!("/ui/r/{router}/routing/policy/new"))
        .with_submit(keys::WEB_ROUTING_POLICY_ADD)
        .with_input(
            Input::new(
                "name",
                keys::WEB_ROUTING_FIELD_POLICY,
                values.text("name").to_owned(),
            )
            .max_chars(64)
            .help(keys::WEB_ROUTING_HELP_POLICY)
            .rule(keys::WEB_ROUTING_ERROR_NAME),
        )
        .with_input(description_input(values))
}

/// The description dialog of the policy `name` on `router` with `values`.
pub(crate) fn description_form(
    locale: Locale,
    router: &str,
    name: &str,
    values: &Params,
) -> FormDialog {
    let mut args = FluentArgs::new();
    args.set("name", name.to_owned());
    let title = tr(
        locale,
        keys::WEB_ROUTING_POLICY_DESCRIPTION_TITLE,
        Some(&args),
    );
    let post_to = with_query(
        &format!("/ui/r/{router}/routing/policy/description"),
        &[("name", name)],
    );
    FormDialog::new(locale, title, post_to)
        .with_submit(keys::COMMON_SAVE)
        .with_input(description_input(values))
}

/// The optional one-word description input with `values`.
fn description_input(values: &Params) -> Input {
    Input::new(
        "description",
        keys::WEB_ROUTING_FIELD_DESCRIPTION,
        values.text("description").to_owned(),
    )
    .max_chars(WORD_CHARS)
    .optional()
    .help(keys::WEB_ROUTING_HELP_WORD)
    .rule(keys::WEB_ROUTING_ERROR_WORD)
}

/// The Add interface dialog of the policy `name` on `router` with `values` and the
/// router's interface `names`.
pub(crate) fn permit_form(
    locale: Locale,
    (router, name): (&str, &str),
    values: &Params,
    names: &[String],
) -> FormDialog {
    let mut args = FluentArgs::new();
    args.set("name", name.to_owned());
    let title = tr(locale, keys::WEB_ROUTING_POLICY_PERMIT_TITLE, Some(&args));
    let post_to = with_query(
        &format!("/ui/r/{router}/routing/policy/permit"),
        &[("name", name)],
    );
    let choices = names.iter().map(|found| Choice::plain(found)).collect();
    FormDialog::new(locale, title, post_to)
        .with_submit(keys::WEB_ROUTING_POLICY_PERMIT)
        .with_input(
            Input::new(
                "interface",
                keys::WEB_ROUTING_FIELD_INTERFACE,
                values.text("interface").to_owned(),
            )
            .select(choices)
            .help(keys::WEB_ROUTING_POLICY_PERMIT_TEXT),
        )
        .with_input(
            Input::new(
                "order",
                keys::WEB_ROUTING_FIELD_ORDER,
                values.text("order").to_owned(),
            )
            .number(0, i64::from(u16::MAX))
            .optional()
            .help(keys::WEB_ROUTING_HELP_ORDER)
            .rule(keys::WEB_ROUTING_ERROR_NUMBER),
        )
}
