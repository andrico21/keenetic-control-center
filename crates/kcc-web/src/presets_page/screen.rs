//! The run page around a step panel: the title, the numbered step list, what the run
//! applies where, and the outcome region; the migration wizard's layout with the presets'
//! steps.
//!
//! A step's panel is its own template; a submit that fails answers with the panel alone
//! (422, swapped into `#wizard-step`), a submit that succeeds sends the browser to the
//! run's page, which shows its next step.

use core::{cmp::Ordering, iter};

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    record::Record,
    steps::{Origin, Step},
};
use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::respond,
};

/// The run page.
#[derive(Template)]
#[template(path = "pages/presets_wizard.html")]
struct Screen {
    /// Page shell.
    shell: Shell,
    /// The page title: a copy or a preset's apply.
    title: String,
    /// "Step N of 9".
    position: String,
    /// The step list.
    steps: Vec<StepItem>,
    /// What the run applies and where, as far as chosen.
    summary: Vec<(String, String)>,
    /// The current step's rendered panel.
    panel: String,
    /// Run id.
    id: String,
    /// The step Back shows, as its form value.
    back: Option<&'static str>,
}

localized!(Screen);

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
    let title = match record.origin() {
        Origin::Preset { id: _, name: _ } => keys::WEB_PRESETS_WIZARD_APPLY,
        Origin::Copy => keys::WEB_PRESETS_WIZARD_COPY,
    };
    let screen = Screen {
        title: tr(locale, title, None),
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

/// The answer to a submit that moved the run on: the browser opens its page.
pub(super) fn moved(record: &Record) -> Response {
    respond::open(&href(record.id()))
}

/// The page of run `id`.
pub(super) fn href(id: &str) -> String {
    format!("/ui/presets/runs/{id}")
}

/// What the run's settings are called: the preset's name, or the copy's source.
pub(super) fn settings_text(record: &Record, locale: Locale) -> String {
    match (record.origin(), record.source_router()) {
        (Origin::Preset { id: _, name }, _) => name.clone(),
        (Origin::Copy, Some(router)) => {
            let mut args = FluentArgs::new();
            args.set("router", router.to_owned());
            tr(locale, keys::WEB_PRESETS_RUN_COPY, Some(&args))
        }
        (Origin::Copy, None) => tr(locale, keys::WEB_PRESETS_RUN_COPY_NEW, None),
    }
}

/// The settings and the target of `record`, as far as chosen.
fn summary(record: &Record, locale: Locale) -> Vec<(String, String)> {
    let settings = (
        tr(locale, keys::WEB_PRESETS_SUMMARY_SETTINGS, None),
        settings_text(record, locale),
    );
    let target = record
        .target()
        .map(|target| (tr(locale, keys::MIGRATE_TARGET, None), target.to_owned()));
    iter::once(settings).chain(target).collect()
}
