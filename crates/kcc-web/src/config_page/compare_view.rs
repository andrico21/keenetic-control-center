//! The form choosing two configurations to compare, and their changes as the page shows
//! them: secrets replaced, unified or side by side.

use askama::Template;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{backup_rows::BackupRow, diff::Changes, text::Lines};
use crate::{
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
};

/// The `to` value naming the router's running configuration.
pub(crate) const RUNNING: &str = "running";

/// One configuration a comparison can start or end at.
#[derive(Debug, Clone)]
pub(crate) struct Choice {
    /// The backup's file name.
    value: String,
    /// Its reason and age.
    label: String,
}

impl Choice {
    /// The backup's file name.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// Its reason and age.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }
}

/// The comparison form: a GET form to the diff page, so it works without JavaScript and
/// its result can be bookmarked.
#[derive(Template)]
#[template(path = "partials/config_compare_form.html")]
pub(crate) struct CompareForm {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The form's heading.
    title: MessageKey,
    /// Every backup, newest first.
    choices: Vec<Choice>,
    /// The chosen older side.
    from: String,
    /// The chosen newer side: a backup or [`RUNNING`].
    to: String,
    /// Whether the changes show side by side.
    split: bool,
}

impl Localize for CompareForm {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl CompareForm {
    /// The form over `rows`, comparing the newest backup with the running configuration.
    pub(crate) fn new(locale: Locale, router: &str, rows: &[BackupRow]) -> Self {
        let choices: Vec<Choice> = rows
            .iter()
            .map(|row| Choice {
                value: row.name().to_owned(),
                label: format!("{} ({})", row.reason(), row.age()),
            })
            .collect();
        Self {
            shell: fragment_shell(locale),
            router: router.to_owned(),
            title: keys::WEB_CONFIG_COMPARE_TITLE,
            from: choices
                .first()
                .map(|choice| choice.value.clone())
                .unwrap_or_default(),
            choices,
            to: RUNNING.to_owned(),
            split: false,
        }
    }

    /// The form with `from` and `to` chosen, side by side when `split`, below a
    /// comparison it changes.
    pub(crate) fn chosen(mut self, (from, to): (&str, &str), split: bool) -> Self {
        from.clone_into(&mut self.from);
        to.clone_into(&mut self.to);
        self.split = split;
        self.title = keys::WEB_CONFIG_COMPARE_AGAIN;
        self
    }

    /// The label of the backup `name`, if listed.
    pub(crate) fn label(&self, name: &str) -> Option<&str> {
        self.choices
            .iter()
            .find(|choice| choice.value == name)
            .map(Choice::label)
    }

    /// Whether `value` is the chosen older side.
    fn is_from(&self, value: &str) -> bool {
        self.from == value
    }

    /// Whether `value` is the chosen newer side.
    fn is_to(&self, value: &str) -> bool {
        self.to == value
    }
}

/// One run of changed lines, secrets replaced.
#[derive(Debug, Clone)]
pub(crate) struct ShownHunk {
    /// The removed lines.
    removed: Vec<String>,
    /// The added lines.
    added: Vec<String>,
}

impl ShownHunk {
    /// The removed lines.
    pub(crate) fn removed(&self) -> &[String] {
        &self.removed
    }

    /// The added lines.
    pub(crate) fn added(&self) -> &[String] {
        &self.added
    }

    /// Side by side: each removed line beside the added line at its position.
    pub(crate) fn rows(&self) -> Vec<(Option<&str>, Option<&str>)> {
        let count = self.removed.len().max(self.added.len());
        (0..count)
            .map(|index| {
                (
                    self.removed.get(index).map(String::as_str),
                    self.added.get(index).map(String::as_str),
                )
            })
            .collect()
    }
}

/// The changes between two configurations as the page shows them.
#[derive(Debug, Clone)]
pub(crate) struct ShownChanges {
    /// The runs of changed lines, in order.
    hunks: Vec<ShownHunk>,
    /// Removed lines.
    removed: usize,
    /// Added lines.
    added: usize,
    /// Whether the order of lines was compared.
    ordered: bool,
}

impl ShownChanges {
    /// The changes from `old` to `new`.
    pub(crate) fn new(old: &Lines, new: &Lines) -> Self {
        let changes = Changes::between(old.digests(), new.digests());
        let hunks = changes
            .hunks()
            .iter()
            .map(|hunk| ShownHunk {
                removed: hunk
                    .removed()
                    .iter()
                    .map(|&index| old.shown(index).to_owned())
                    .collect(),
                added: hunk
                    .added()
                    .iter()
                    .map(|&index| new.shown(index).to_owned())
                    .collect(),
            })
            .collect();
        Self {
            hunks,
            removed: changes.removed(),
            added: changes.added(),
            ordered: changes.ordered(),
        }
    }

    /// The runs of changed lines.
    pub(crate) fn hunks(&self) -> &[ShownHunk] {
        &self.hunks
    }

    /// Removed lines.
    pub(crate) const fn removed(&self) -> usize {
        self.removed
    }

    /// Added lines.
    pub(crate) const fn added(&self) -> usize {
        self.added
    }

    /// Whether the order of lines was compared.
    pub(crate) const fn ordered(&self) -> bool {
        self.ordered
    }

    /// Whether nothing changed.
    pub(crate) const fn is_empty(&self) -> bool {
        self.hunks.is_empty()
    }
}
