//! `GET /ui/admin/mcp/status`: the restart status fragment, polled every 2 seconds while
//! the restart runs and until its deadline.

use askama::Template;
use axum::{
    extract::{Query, State},
    response::Response,
};
use kcc_app::mcp_settings::ListenerKind;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{Progress, messages::Said, page::fresh, view::Region};
use crate::{
    WebState, admin_shared::unavailable, authz::CurrentUser, errors, page::Shell,
    page_kit::context::fragment_shell,
};

/// The fragment's query: the Unix second polling stops.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusQuery {
    /// The last second the fragment polls.
    until: u64,
}

/// What the fragment says.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shown {
    /// Nothing: no restart since the start.
    Nothing,
    /// The restart runs; poll again until the deadline.
    Running(String),
    /// The restart outlived its deadline.
    Late(String),
    /// The restart's outcome, in the notice's tone.
    Ended(Said, &'static str),
}

/// The restart status fragment.
#[derive(Template)]
#[template(path = "partials/admin_mcp_status.html")]
pub(crate) struct Status {
    /// Locale carrier.
    shell: Shell,
    /// The deadline of the polling.
    until: u64,
    /// What it says.
    shown: Shown,
    /// The settings region read again once the restart ended, out of band.
    region: Option<Region>,
}

localized!(Status);
fragment!(Status);

impl Status {
    /// The fragment of `progress` in `locale` at the Unix second `now`, polling until
    /// `until`.
    pub(crate) fn new(locale: Locale, progress: &Progress, (now, until): (u64, u64)) -> Self {
        let shown = match progress {
            Progress::Idle => Shown::Nothing,
            Progress::Restarting(_) if now > until => {
                Shown::Late(tr(locale, keys::WEB_ADMIN_MCP_RESTART_TIMEOUT, None))
            }
            Progress::Restarting(kinds) => Shown::Running(restarting(locale, kinds)),
            Progress::Applied => Shown::Ended(
                Said::new(locale, keys::WEB_ADMIN_MCP_RESTART_APPLIED, None),
                "success",
            ),
            Progress::Refused(refusal) => Shown::Ended(Said::refusal(locale, *refusal), "error"),
        };
        Self {
            shell: fragment_shell(locale),
            until,
            shown,
            region: None,
        }
    }

    /// Whether the restart ended: applied, refused or reverted.
    const fn ended(&self) -> bool {
        matches!(self.shown, Shown::Ended(..))
    }

    /// Whether the fragment polls again.
    const fn polling(&self) -> bool {
        matches!(self.shown, Shown::Running(_))
    }
}

/// "Restarting the main and dedicated listener" in `locale`.
fn restarting(locale: Locale, kinds: &[ListenerKind]) -> String {
    let names: Vec<String> = kinds
        .iter()
        .map(|kind| tr(locale, super::messages::listener(*kind), None))
        .collect();
    Said::new(
        locale,
        keys::WEB_ADMIN_MCP_RESTARTING,
        Some(("what", names.join(", "))),
    )
    .text()
    .to_owned()
}

/// `GET /ui/admin/mcp/status?until=<unix>`. Once the restart ended, the settings region
/// read again comes along out of band, so the page shows the settings now in force.
// cancel-safe: it only reads the page's restart progress and local state on a blocking
// thread.
pub(crate) async fn status(
    State(state): State<WebState>,
    user: CurrentUser,
    Query(query): Query<StatusQuery>,
) -> Response {
    let Some(attached) = state.mcp() else {
        return unavailable(None);
    };
    let locale = user.locale();
    let mut fragment = Status::new(
        locale,
        &attached.progress(),
        (state.unix_seconds(), query.until),
    );
    if fragment.ended() {
        match fresh(&state, locale).await {
            Ok(region) => fragment.region = Some(region),
            Err(error) => tracing::error!(%error, "MCP settings region could not be read again"),
        }
    }
    errors::render(&fragment)
}
