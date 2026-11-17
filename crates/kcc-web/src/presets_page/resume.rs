//! Resuming a run at its current step (`crate::wizard::resume`): the step's panel.

use axum::response::Response;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    access::Visit,
    inputs, options, preview,
    review::{self, View},
    source,
    steps::Step,
    target,
};
use crate::{
    WebState,
    page::Shell,
    wizard::{flow::Flow as _, report::Panel, results, running, screen},
};

/// The report's files to download.
const DOWNLOADS: [(&str, MessageKey); 2] = [
    ("report.md", keys::WEB_MIGRATE_DOWNLOAD_MARKDOWN),
    ("report.json", keys::WEB_MIGRATE_DOWNLOAD_JSON),
];

/// The page of the run `visit` opened, at its current step.
// cancel-safe: reads only.
pub(super) async fn show(
    visit: &Visit<'_>,
    shell: Shell,
    (view, state): (&View, &WebState),
) -> Response {
    let record = visit.record();
    match record.step() {
        Step::Source => {
            let chosen = (record.source_router(), [].as_slice());
            let panel = source::Panel::new(visit.services(), record.id(), chosen).await;
            screen::page(shell, record, &panel)
        }
        Step::Target => screen::page(shell, record, &target::Panel::new(visit).await),
        Step::Options => screen::page(shell, record, &options::Panel::new(visit).await),
        Step::Review => screen::page(shell, record, &review::Panel::new(visit, view).await),
        Step::Inputs => screen::page(shell, record, &inputs::Panel::new(visit, &[]).await),
        Step::Preview => {
            let panel = preview::Panel::new(visit, state).await;
            screen::page(shell, record, &panel)
        }
        Step::Apply => {
            let words = (keys::WEB_PRESETS_RUN_TITLE, keys::WEB_PRESETS_RUN_TEXT);
            screen::page(shell, record, &running::Panel::new(visit, words))
        }
        Step::Results => screen::page(shell, record, &results::Panel::new(visit).await),
        Step::Report => {
            let panel = Panel::new(visit)
                .with_keys(record.keys(), record.kept_keys())
                .with_downloads(keys::WEB_PRESETS_DOWNLOADS, &DOWNLOADS);
            screen::page(shell, record, &panel)
        }
    }
}
