//! Step 9: how the run finished, what it sent, the new WireGuard public keys to register
//! on the VPN servers, and the report to download.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys};

use super::{access::Visit, results::facts, steps::Finish};
use crate::{
    admin_shared::Timestamp,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_report.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
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
    /// New WireGuard public keys: interface and key.
    keys: Vec<(String, String)>,
    /// One warning per interface whose captured private key was copied.
    kept: Vec<String>,
}

localized!(Panel);

impl Panel {
    /// The report of `visit`.
    pub(super) fn new(visit: &Visit<'_>) -> Self {
        let locale = visit.services().user().locale();
        let record = visit.record();
        let (how, at) = record.finished().unwrap_or((Finish::Closed, 0));
        let tone = match how {
            Finish::KeptUnsaved | Finish::Saved => "success",
            Finish::RolledBack
            | Finish::RolledBackByRouter
            | Finish::RollbackRestarting
            | Finish::Closed => "info",
        };
        Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            tone,
            message: tr(locale, how.text(), None),
            finished: (at > 0).then(|| Timestamp::at(at)).flatten(),
            facts: record
                .run()
                .and_then(|run| run.ended())
                .map_or_else(Vec::new, |end| facts(end.applied(), end.failed(), locale)),
            keys: record.keys().to_vec(),
            kept: record
                .kept_keys()
                .iter()
                .map(|name| {
                    let mut args = FluentArgs::new();
                    args.set("name", name.clone());
                    tr(locale, keys::WEB_PRESETS_KEYS_KEPT, Some(&args))
                })
                .collect(),
        }
    }
}
