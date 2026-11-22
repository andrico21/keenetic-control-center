//! One setting as the page shows it: its label, where its value comes from, and either a
//! form control or, for a value the environment or `[mcp] locked` sets, text only.

use kcc_app::mcp_settings::{Effective, Source, keys::KeyPath};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Serialize;

use super::{
    Choice, Control, Row,
    messages::{label, source},
};

/// Builds the rows of one locale over the effective settings.
pub(crate) struct Rows<'view> {
    /// The page's locale.
    locale: Locale,
    /// The effective settings.
    effective: &'view Effective,
    /// Whether changes can be saved: the listeners run here.
    editable: bool,
}

impl<'view> Rows<'view> {
    /// The rows of `effective` in `locale`, offering resets when `editable`.
    pub(crate) const fn new(locale: Locale, effective: &'view Effective, editable: bool) -> Self {
        Self {
            locale,
            effective,
            editable,
        }
    }

    /// `key` in this locale.
    pub(crate) fn say(&self, key: MessageKey) -> String {
        tr(self.locale, key, None)
    }

    /// The row of `key` edited by `control`, shown as `shown` when fixed.
    pub(crate) fn row(&self, key: KeyPath, control: Control) -> Row {
        let from = self.effective.source(key);
        let shown = shown(&control, |message| self.say(message));
        Row {
            name: key.as_str(),
            id: format!("mcp-{}", key.as_str().replace(['.', '_'], "-")),
            label: self.say(label(key)),
            source: self.say(source(from)),
            fixed: matches!(from, Source::Env | Source::Locked),
            shown,
            reset: self.editable && from == Source::State,
            control,
        }
    }

    /// A checkbox row of `key` at `on`.
    pub(crate) fn check(&self, key: KeyPath, on: bool) -> Row {
        self.row(key, Control::Check(on))
    }

    /// A drop-down row of `key` over `(value, label)` options with `current` chosen.
    pub(crate) fn select<T>(&self, key: KeyPath, current: &T, options: &[(&str, MessageKey)]) -> Row
    where
        T: Serialize,
    {
        let now = name(current);
        let choices = options
            .iter()
            .map(|(value, words)| Choice::new((*value).to_owned(), self.say(*words), *value == now))
            .collect();
        self.row(key, Control::Select(choices))
    }

    /// A drop-down row of `key` over `roles`, with an unset option while `current` is none.
    pub(crate) fn role(&self, key: KeyPath, current: Option<&str>, roles: &[String]) -> Row {
        let mut choices: Vec<Choice> = Vec::new();
        if current.is_none() {
            choices.push(Choice::new(
                String::new(),
                self.say(keys::WEB_ADMIN_MCP_UNSET),
                true,
            ));
        }
        choices.extend(
            roles.iter().map(|role| {
                Choice::new(role.clone(), role.clone(), current == Some(role.as_str()))
            }),
        );
        self.row(key, Control::Select(choices))
    }

    /// A text row of `key` holding `value`, or empty when unset.
    pub(crate) fn text(&self, key: KeyPath, value: Option<String>) -> Row {
        self.row(key, Control::Text(value.unwrap_or_default(), "text"))
    }
}

/// The serde name of `value`, such as `self_signed`.
pub(crate) fn name<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_value(value)
        .ok()
        .and_then(|named| named.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// What a fixed `control` shows as text.
fn shown<F>(control: &Control, say: F) -> String
where
    F: Fn(MessageKey) -> String,
{
    let unset = || say(keys::WEB_ADMIN_MCP_UNSET);
    let listed = |items: Vec<String>| {
        if items.is_empty() {
            unset()
        } else {
            items.join(", ")
        }
    };
    match control {
        Control::Check(on) => say(if *on {
            keys::COMMON_ENABLED
        } else {
            keys::COMMON_DISABLED
        }),
        Control::Text(value, _) if value.is_empty() => unset(),
        Control::Text(value, _) => value.clone(),
        Control::Select(choices) => choices
            .iter()
            .find(|choice| choice.chosen)
            .map_or_else(unset, |choice| choice.label.clone()),
        Control::Checks(choices) => listed(
            choices
                .iter()
                .filter(|choice| choice.chosen)
                .map(|choice| choice.value.clone())
                .collect(),
        ),
        Control::Mappings(table) => listed(
            table
                .rows
                .iter()
                .filter(|(value, _)| !value.is_empty())
                .map(|(value, role)| format!("{value} -> {role}"))
                .collect(),
        ),
    }
}
