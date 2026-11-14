//! Resuming a migration at its current step (`crate::wizard::resume`): the step's panel,
//! and the report kept from the plan the apply used.

use axum::response::Response;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    access::Visit,
    inputs::{self, Shown},
    kinds::Step,
    mapping, preview, results,
    review::{self, View},
    source, target,
};
use crate::{
    page::Shell,
    wizard::{flow::Flow as _, report::Panel, running, screen, store::Kept},
};

/// The report's files to download, once the report was kept.
const DOWNLOADS: [(&str, MessageKey); 4] = [
    ("report.html", keys::WEB_MIGRATE_DOWNLOAD_HTML),
    ("report.md", keys::WEB_MIGRATE_DOWNLOAD_MARKDOWN),
    ("report.json", keys::WEB_MIGRATE_DOWNLOAD_JSON),
    ("plan.json", keys::WEB_MIGRATE_DOWNLOAD_PLAN),
];

/// The page of the migration `visit` opened, at its current step.
// cancel-safe: reads only.
pub(super) async fn show(visit: &Visit<'_>, shell: Shell, view: &View) -> Response {
    let record = visit.record();
    match record.step() {
        Step::Source => {
            let services = visit.services();
            let panel = source::Panel::new(services, record.id(), record.source()).await;
            screen::page(shell, record, &panel)
        }
        Step::Target => screen::page(shell, record, &target::Panel::new(visit).await),
        Step::Mapping => screen::page(shell, record, &mapping::Panel::new(visit).await),
        Step::Review => screen::page(shell, record, &review::Panel::new(visit, view).await),
        Step::Inputs => {
            let panel = inputs::Panel::new(visit, Shown::default()).await;
            screen::page(shell, record, &panel)
        }
        Step::Preview => screen::page(shell, record, &preview::Panel::new(visit).await),
        Step::Apply => {
            let words = (keys::WEB_MIGRATE_RUN_TITLE, keys::WEB_MIGRATE_RUN_TEXT);
            screen::page(shell, record, &running::Panel::new(visit, words))
        }
        Step::Results => screen::page(shell, record, &results::Panel::new(visit).await),
        Step::Report => screen::page(shell, record, &report(visit)),
    }
}

/// Step 9 of `visit`: the report, with its files once they were kept.
fn report(visit: &Visit<'_>) -> Panel {
    let kept = visit
        .services()
        .store()
        .kept(visit.record().id(), Kept::Report)
        .is_ok_and(|kept| kept.is_some());
    let panel = Panel::new(visit);
    if kept {
        panel.with_downloads(keys::WEB_MIGRATE_DOWNLOADS, &DOWNLOADS)
    } else {
        panel
    }
}
