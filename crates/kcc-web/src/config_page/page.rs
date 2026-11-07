//! The page at `/ui/r/{router}/config` and the answers of its actions.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_i18n::keys;

use super::{backups::BackupsRegion, status::StatusRegion};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    fleet::BackupServices,
    nav::Section,
    page::{Localize, Shell},
    page_kit::{
        context::{self, Caller},
        outcome::Outcome,
    },
    system_pages::shared::{answer, rendered, shown_query},
    table::rows::TableQuery,
};

/// The page.
#[derive(Template)]
#[template(path = "pages/config.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Unsaved changes and the fail-safe timer.
    status: StatusRegion,
    /// The backups.
    backups: BackupsRegion,
}

impl Localize for Page {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/r/{router}/config`: the router's configuration state and its backups.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<TableQuery>,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Configuration, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let status = StatusRegion::read(&state, target, &user).await;
    let backups = BackupsRegion::read(Visit::new(&state, &user, &router), &query).await;
    errors::render(&Page {
        shell,
        router,
        status,
        backups,
    })
}

/// Who acts on which router's configuration page.
#[derive(Clone, Copy)]
pub(crate) struct Visit<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
}

impl<'call> Visit<'call> {
    /// `user` on the page of `router`.
    pub(crate) const fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Self {
        Self {
            state,
            user,
            router,
        }
    }

    /// The signed-in user.
    pub(crate) const fn user(self) -> &'call CurrentUser {
        self.user
    }

    /// Router profile id.
    pub(crate) const fn router(self) -> &'call str {
        self.router
    }

    /// The backup store and its retention, when attached.
    pub(crate) fn backups(self) -> Option<&'call BackupServices> {
        self.state.fleet()?.backups()
    }

    /// The current Unix second.
    pub(crate) fn now(self) -> u64 {
        self.state.unix_seconds()
    }

    /// The answer to a change of the configuration state: the outcome, and after a
    /// success the status region read again, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn answer_status(self, outcome: Outcome) -> Response {
        let refreshed = if outcome.succeeded() {
            match context::target(self.state, self.user, self.router).await {
                Ok(target) => rendered(
                    &StatusRegion::read(self.state, target, self.user)
                        .await
                        .out_of_band(),
                ),
                Err(_refusal) => None,
            }
        } else {
            None
        };
        answer(outcome, refreshed, self.user.locale())
    }

    /// The answer to a change of the backups: the outcome, and after a success the
    /// backups region listed again as the browser shows it, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn answer_backups(self, outcome: Outcome, headers: &HeaderMap) -> Response {
        let refreshed = if outcome.succeeded() {
            let query = shown_query(headers);
            rendered(&BackupsRegion::read(self, &query).await.out_of_band())
        } else {
            None
        };
        answer(outcome, refreshed, self.user.locale())
    }
}
