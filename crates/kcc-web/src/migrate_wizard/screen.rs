//! The wizard page around a step panel: the title, the numbered step list, what the
//! migration moves from where to where, and the outcome region.
//!
//! A step's panel is its own template; a submit that fails answers with the panel alone
//! (422, swapped into `#wizard-step`), a submit that succeeds sends the browser to the
//! migration's page, which shows its next step.

use core::cmp::Ordering;

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    kinds::{Mode, Source, Step},
    record::Record,
};
use crate::{
    errors,
    page::{Localize, Shell},
    page_kit::respond,
};

/// The wizard page.
#[derive(Template)]
#[template(path = "pages/migrate_wizard.html")]
pub(super) struct Screen {
    /// Page shell.
    shell: Shell,
    /// The page title: a migration or a restore.
    title: String,
    /// "Step N of 9".
    position: String,
    /// The step list.
    steps: Vec<StepItem>,
    /// Source and target, as far as chosen.
    summary: Vec<Fact>,
    /// The current step's rendered panel.
    panel: String,
    /// Migration id.
    id: String,
    /// The step Back shows, as its form value.
    back: Option<&'static str>,
}

impl Localize for Screen {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// One entry of the step list.
struct StepItem {
    /// 1 to 9.
    number: u32,
    /// The step's name.
    label: String,
    /// `done`, `current` or `todo`.
    state: &'static str,
    /// Whether it is the current step.
    current: bool,
}

/// One label and value of the summary.
struct Fact {
    /// Localized label.
    label: String,
    /// The value.
    value: String,
}

/// The page of `record` showing `panel`.
pub(super) fn page<T>(shell: Shell, record: &Record, panel: &T) -> Response
where
    T: Template,
{
    let locale = shell.locale();
    let rendered = match panel.render() {
        Ok(html) => html,
        Err(error) => return errors::internal(&error, shell),
    };
    let mut args = FluentArgs::new();
    args.set("current", record.step().number());
    args.set("total", 9_u32);
    let screen = Screen {
        title: tr(locale, title(record.mode()), None),
        position: tr(locale, keys::MIGRATE_STEP, Some(&args)),
        steps: Step::ALL
            .iter()
            .map(|step| StepItem {
                number: step.number(),
                label: tr(locale, step.label(), None),
                state: match step.cmp(&record.step()) {
                    Ordering::Less => "done",
                    Ordering::Equal => "current",
                    Ordering::Greater => "todo",
                },
                current: *step == record.step(),
            })
            .collect(),
        summary: summary(record, locale),
        panel: rendered,
        id: record.id().to_owned(),
        back: record.previous().map(Step::slug),
        shell,
    };
    errors::render(&screen)
}

/// The answer to a submit that moved the migration on: the browser opens its page.
pub(super) fn moved(record: &Record) -> Response {
    respond::open(&href(record.id()))
}

/// The page of migration `id`.
pub(super) fn href(id: &str) -> String {
    format!("/ui/migrate/{id}")
}

/// The title of a wizard in `mode`.
pub(super) const fn title(mode: Mode) -> MessageKey {
    match mode {
        Mode::Migrate => keys::MIGRATE_TITLE,
        Mode::Restore => keys::WEB_MIGRATE_RESTORE_TITLE,
    }
}

/// How `source` is named in the summary and the migration list.
pub(super) fn source_text(source: &Source, locale: Locale) -> String {
    let mut args = FluentArgs::new();
    let key = match source {
        Source::Router { router } => {
            args.set("router", router.clone());
            keys::WEB_MIGRATE_SOURCE_IS_ROUTER
        }
        Source::File { name } => {
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_FILE
        }
        Source::Backup { router, name } => {
            args.set("router", router.clone());
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_BACKUP
        }
    };
    tr(locale, key, Some(&args))
}

/// Source and target of `record`, as far as chosen.
fn summary(record: &Record, locale: Locale) -> Vec<Fact> {
    let source = record.source().map(|source| Fact {
        label: tr(locale, keys::WEB_MIGRATE_SUMMARY_SOURCE, None),
        value: source_text(source, locale),
    });
    let target = record.target().map(|target| Fact {
        label: tr(locale, keys::MIGRATE_TARGET, None),
        value: target.to_owned(),
    });
    source.into_iter().chain(target).collect()
}
