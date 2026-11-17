//! The new preset's groups panel: the groups, the redacted captured settings, the name
//! and the description, with their errors.

use alloc::collections::BTreeSet;

use askama::Template;
use kcc_config::config_text::{Ast, parse};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::presets::groups::SettingsGroupEngine;
use secrecy::ExposeSecret as _;

use super::{
    drafts::Draft,
    lines::{count, group_words, selected, shown},
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, request::last},
    wizard::source::source_text,
};

/// The longest name, in characters.
const NAME_MAX: usize = 64;

/// The longest description, in characters.
const DESCRIPTION_MAX: usize = 256;

/// The groups, the captured settings, the name and description.
#[derive(Template)]
#[template(path = "partials/presets_compose.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Draft id; empty when the draft is gone.
    id: String,
    /// Where the source came from.
    source: String,
    /// Its model and firmware.
    facts: (String, String),
    /// Every group.
    groups: Vec<Choice>,
    /// The typed name, its error.
    named: (String, String),
    /// The typed description, its error.
    described: (String, String),
    /// The groups' error.
    groups_error: String,
    /// The captured settings, redacted.
    lines: Vec<String>,
    /// How many there are.
    total: String,
}

localized!(Panel);

/// One group's checkbox.
struct Choice {
    /// Group id, the form value.
    id: String,
    /// Its name.
    title: String,
    /// What it takes.
    text: String,
    /// How many settings of the source it takes.
    count: String,
    /// Whether it is chosen.
    checked: bool,
}

/// The captured settings of the chosen groups, redacted.
#[derive(Template)]
#[template(path = "partials/presets_captured.html")]
pub(super) struct Captured {
    /// Locale carrier.
    shell: Shell,
    /// The lines.
    lines: Vec<String>,
    /// How many there are.
    total: String,
}

localized!(Captured);

/// What the form sent.
pub(super) struct Submitted {
    /// The chosen groups.
    groups: Vec<String>,
    /// The typed name, trimmed.
    name: String,
    /// The typed description, trimmed.
    description: String,
}

impl Submitted {
    /// The fields of `form`.
    pub(super) fn of(form: &[(String, String)]) -> Self {
        let value = |field: &str| {
            last(form, field).map_or_else(String::new, |typed| typed.trim().to_owned())
        };
        Self {
            groups: form
                .iter()
                .filter(|(name, _)| name == "group")
                .map(|(_, id)| id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            name: value("name"),
            description: value("description"),
        }
    }

    /// The chosen groups.
    pub(super) fn groups(&self) -> &[String] {
        &self.groups
    }

    /// The chosen groups, the typed name and description.
    pub(super) fn into_parts(self) -> (Vec<String>, String, String) {
        (self.groups, self.name, self.description)
    }
}

impl Panel {
    /// The panel of `draft` (`None` when it is gone), with the choices and errors of
    /// `submitted` when the form was sent.
    pub(super) fn new(
        locale: Locale,
        id: &str,
        draft: Option<&Draft>,
        submitted: Option<&Submitted>,
    ) -> Self {
        let shell = fragment_shell(locale);
        let Some(found) = draft else {
            return Self {
                shell,
                id: String::new(),
                source: String::new(),
                facts: (String::new(), String::new()),
                groups: Vec::new(),
                named: (String::new(), String::new()),
                described: (String::new(), String::new()),
                groups_error: String::new(),
                lines: Vec::new(),
                total: String::new(),
            };
        };
        let empty = Submitted::of(&[]);
        let chosen = submitted.unwrap_or(&empty);
        let ast = source_ast(found).unwrap_or_default();
        let groups = SettingsGroupEngine::embedded()
            .and_then(SettingsGroupEngine::groups)
            .unwrap_or_default()
            .iter()
            .filter_map(|group| {
                let (title, text) = group_words(&group.id)?;
                let size = selected(&ast, &[group.id.as_str()]).len();
                Some(Choice {
                    id: group.id.clone(),
                    title: tr(locale, title, None),
                    text: tr(locale, text, None),
                    count: count(locale, size),
                    checked: chosen.groups.contains(&group.id),
                })
            })
            .collect();
        let captured = captured(locale, found, &chosen.groups);
        let errors = submitted.map_or_else(Errors::default, |sent| {
            Errors::of(sent, captured.lines.is_empty(), locale)
        });
        Self {
            shell,
            id: id.to_owned(),
            source: source_text(found.source(), locale),
            facts: (found.model().to_owned(), found.firmware().to_owned()),
            groups,
            named: (chosen.name.clone(), errors.name),
            described: (chosen.description.clone(), errors.description),
            groups_error: errors.groups,
            lines: captured.lines,
            total: captured.total,
        }
    }

    /// Whether the panel shows an error: nothing can be saved.
    pub(super) const fn refusing(&self) -> bool {
        self.id.is_empty()
            || !self.named.1.is_empty()
            || !self.described.1.is_empty()
            || !self.groups_error.is_empty()
    }
}

/// The errors of a submitted form; empty strings where a field is fine.
#[derive(Default)]
struct Errors {
    /// The name's.
    name: String,
    /// The description's.
    description: String,
    /// The groups'.
    groups: String,
}

impl Errors {
    /// The errors of `submitted`, whose groups capture nothing when `empty`.
    fn of(submitted: &Submitted, empty: bool, locale: Locale) -> Self {
        let refuse = |wrong: bool, key| {
            if wrong {
                tr(locale, key, None)
            } else {
                String::new()
            }
        };
        let name = submitted.name.chars().count();
        let description = submitted.description.chars().count();
        Self {
            name: refuse(
                !(1..=NAME_MAX).contains(&name) || submitted.name.chars().any(char::is_control),
                keys::WEB_PRESETS_ERROR_NAME,
            ),
            description: refuse(
                description > DESCRIPTION_MAX
                    || submitted.description.chars().any(char::is_control),
                keys::WEB_PRESETS_ERROR_DESCRIPTION,
            ),
            groups: refuse(empty, keys::WEB_PRESETS_ERROR_GROUPS),
        }
    }
}

/// The captured settings of `groups` in `draft`, redacted.
pub(super) fn captured(locale: Locale, draft: &Draft, groups: &[String]) -> Captured {
    let chosen = groups
        .iter()
        .filter(|group| group_words(group).is_some())
        .map(String::as_str)
        .collect::<Vec<_>>();
    let lines = if chosen.is_empty() {
        Vec::new()
    } else {
        source_ast(draft).map_or_default(|ast| selected(&ast, &chosen).iter().map(shown).collect())
    };
    Captured {
        shell: fragment_shell(locale),
        total: count(locale, lines.len()),
        lines,
    }
}

/// The parsed source configuration of `draft`.
pub(super) fn source_ast(draft: &Draft) -> Option<Ast> {
    parse(draft.text().expose_secret()).ok()
}
