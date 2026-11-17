//! Step 9: how the run finished, what it sent, and the report to download.
//!
//! Each wizard's files are answered as an [`respond::attachment`]; a preset run also lists the new
//! WireGuard public keys to register on the VPN servers.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{flow::Flow, visit::Visit};
use crate::{
    admin_shared::Timestamp,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    table::{cells::Cell, head::Head, piece::Piece, view::TableView},
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/wizard_report.html")]
pub(crate) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Where the wizard's run pages are.
    prefix: &'static str,
    /// Run id.
    id: String,
    /// Notice tone of the end.
    tone: &'static str,
    /// How it finished.
    message: String,
    /// When it finished.
    finished: Option<Timestamp>,
    /// What the apply did.
    facts: Vec<(String, String)>,
    /// One warning per interface whose captured private key was copied.
    kept: Vec<String>,
    /// The table of the new WireGuard public keys, when there are some.
    public_keys: Option<TableView>,
    /// The downloads' heading, when the report can be downloaded.
    downloads_title: Option<String>,
    /// The files to download: file name and link text.
    downloads: Vec<(&'static str, String)>,
    /// The page listing the wizard's runs.
    list: &'static str,
    /// The link to that page.
    all: String,
}

localized!(Panel);

impl Panel {
    /// The report of `visit`, without downloads.
    pub(crate) fn new<F>(visit: &Visit<'_, F>) -> Self
    where
        F: Flow,
    {
        let locale = visit.services().user().locale();
        let record = visit.record();
        let (how, at) = record.finished().unwrap_or((F::CLOSED, 0));
        let facts = record
            .run()
            .and_then(|run| run.ended())
            .map_or_else(Vec::new, |end| {
                vec![
                    (
                        tr(locale, keys::WEB_MIGRATE_COUNT_APPLIED, None),
                        end.applied().to_string(),
                    ),
                    (
                        tr(locale, keys::WEB_MIGRATE_COUNT_REFUSED, None),
                        end.failed().to_string(),
                    ),
                ]
            });
        Self {
            shell: fragment_shell(locale),
            prefix: F::PREFIX,
            id: record.id().to_owned(),
            tone: if F::succeeded(how) { "success" } else { "info" },
            message: tr(locale, F::finish_text(how), None),
            finished: (at > 0).then(|| Timestamp::at(at, locale)).flatten(),
            facts,
            kept: Vec::new(),
            public_keys: None,
            downloads_title: None,
            downloads: Vec::new(),
            list: F::LIST,
            all: tr(locale, F::ALL, None),
        }
    }

    /// The report with the `files` to download (file name and link text) under `title`.
    pub(crate) fn with_downloads(
        mut self,
        title: MessageKey,
        files: &[(&'static str, MessageKey)],
    ) -> Self {
        let locale = self.shell.locale();
        self.downloads_title = Some(tr(locale, title, None));
        self.downloads = files
            .iter()
            .map(|(file, label)| (*file, tr(locale, *label, None)))
            .collect();
        self
    }

    /// The report with the new WireGuard `public` keys (interface and key) and the
    /// interfaces whose captured private key was copied, `kept`.
    pub(crate) fn with_keys(mut self, public: &[(String, String)], kept: &[String]) -> Self {
        let locale = self.shell.locale();
        self.public_keys = (!public.is_empty()).then(|| {
            let mut view = TableView::new("table")
                .wrapped("table-wrap presets-keys")
                .compact()
                .head(Head::plain(tr(
                    locale,
                    keys::WEB_PRESETS_KEYS_INTERFACE,
                    None,
                )))
                .head(Head::plain(tr(locale, keys::WEB_PRESETS_KEYS_KEY, None)));
            for (interface, public_key) in public {
                let code = Piece::element("code", public_key.clone())
                    .attr("class", "wizard-line".to_owned());
                view = view.row(vec![
                    Cell::code(interface.clone()).head(),
                    Cell::of(vec![code]),
                ]);
            }
            view
        });
        self.kept = kept
            .iter()
            .map(|name| {
                let mut args = FluentArgs::new();
                args.set("name", name.clone());
                tr(locale, keys::WEB_PRESETS_KEYS_KEPT, Some(&args))
            })
            .collect();
        self
    }
}
