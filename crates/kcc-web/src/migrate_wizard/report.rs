//! Step 9: how the migration finished, what it sent, and the report to download (kept
//! from the plan the apply used).

use askama::Template;
use kcc_i18n::{bundle::tr, keys};

use super::{access::Visit, run::Finish, store::Kept};
use crate::{
    admin_shared::Timestamp,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_report.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// Notice tone of the end.
    tone: &'static str,
    /// How it finished.
    message: String,
    /// When it finished.
    finished: Option<Timestamp>,
    /// What the apply did.
    facts: Vec<(String, String)>,
    /// Whether the report was kept.
    downloads: bool,
}

localized!(Panel);

impl Panel {
    /// The report of `visit`.
    pub(super) fn new(visit: &Visit<'_>) -> Self {
        let services = visit.services();
        let locale = services.user().locale();
        let record = visit.record();
        let (how, at) = record.finished().unwrap_or((Finish::Closed, 0));
        let tone = if how == Finish::Committed {
            "success"
        } else {
            "info"
        };
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
        let downloads = services
            .store()
            .kept(record.id(), Kept::Report)
            .is_ok_and(|kept| kept.is_some());
        Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            tone,
            message: tr(locale, how.text(), None),
            finished: (at > 0).then(|| Timestamp::at(at)).flatten(),
            facts,
            downloads,
        }
    }
}
