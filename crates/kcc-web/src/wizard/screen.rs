//! The wizard page around a step panel: the title, the numbered step list, what the run
//! works on, and the outcome region.
//!
//! A step's panel is its own template; a submit that fails answers with the panel alone
//! (422, swapped into `#wizard-step`), a submit that succeeds sends the browser to the
//! run's page, which shows its next step.

use core::cmp::Ordering;

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use super::flow::{Flow, Stage};
use crate::{
    errors,
    markup::Rendered,
    page::{Localize, Shell},
    page_kit::respond,
};

/// The wizard page.
#[derive(Template)]
#[template(path = "pages/wizard.html")]
struct Screen {
    /// Page shell.
    shell: Shell,
    /// The page title.
    title: String,
    /// The page listing the wizard's runs.
    list: &'static str,
    /// The link to that page.
    all: String,
    /// The step list's name.
    steps_label: String,
    /// "Step N of 9".
    position: String,
    /// The step list.
    steps: Vec<StepItem>,
    /// What the run works on, as far as chosen: label and value.
    summary: Vec<(String, String)>,
    /// The current step's rendered panel.
    panel: Rendered,
    /// Where the wizard's run pages are.
    prefix: &'static str,
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
pub(crate) fn page<F, T>(shell: Shell, record: &F, panel: &T) -> Response
where
    F: Flow,
    T: Template,
{
    let locale = shell.locale();
    let rendered = match Rendered::of(panel) {
        Ok(html) => html,
        Err(error) => return errors::internal(&error, shell),
    };
    let current = record.step();
    let mut args = FluentArgs::new();
    args.set("current", current.number());
    args.set("total", F::Step::ALL.len());
    let screen = Screen {
        title: tr(locale, record.title(), None),
        list: F::LIST,
        all: tr(locale, F::ALL, None),
        steps_label: tr(locale, F::STEPS_LABEL, None),
        position: tr(locale, keys::MIGRATE_STEP, Some(&args)),
        steps: F::Step::ALL
            .iter()
            .map(|step| StepItem {
                number: step.number(),
                label: tr(locale, step.label(), None),
                state: match step.cmp(&current) {
                    Ordering::Less => "done",
                    Ordering::Equal => "current",
                    Ordering::Greater => "todo",
                },
                current: *step == current,
            })
            .collect(),
        summary: record.summary(locale),
        panel: rendered,
        prefix: F::PREFIX,
        id: record.id().to_owned(),
        back: record.previous().map(Stage::slug),
        shell,
    };
    errors::render(&screen)
}

/// The answer to a submit that moved the run on: the browser opens its page.
pub(crate) fn moved<F>(record: &F) -> Response
where
    F: Flow,
{
    respond::open(&href::<F>(record.id()))
}

/// The page of run `id`.
pub(crate) fn href<F>(id: &str) -> String
where
    F: Flow,
{
    format!("{}/{id}", F::PREFIX)
}

/// `panel` as the step's answer to a confirmed request that failed (422): shown in the
/// step, whatever the request targeted, with the dialog closed.
pub(crate) fn refused<T>(panel: &T) -> Response
where
    T: Template + Localize,
{
    respond::close_dialog(respond::retarget(
        respond::unprocessable(panel),
        "#wizard-step",
    ))
}

/// A count labelled `key`, as a step's facts list it.
pub(crate) fn fact(locale: Locale, key: MessageKey, count: usize) -> (String, String) {
    let value = u64::try_from(count).unwrap_or(u64::MAX);
    (tr(locale, key, None), format::integer(locale, value))
}
