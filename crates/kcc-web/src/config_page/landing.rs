//! `GET /ui/configuration` (route table: `Write`): every router the user may read, with
//! its configuration and backups page.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_i18n::{bundle::tr, keys};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::Caller,
    table::{cells::Cell, fleet::routers_table, piece::Piece, view::TableView},
};

/// The landing page.
#[derive(Template)]
#[template(path = "pages/config_landing.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// One row per router: its id and its configuration page.
    table: TableView,
}

localized!(Page);

impl Page {
    /// The page in `shell` over the router ids `routers` (none while fleet services are
    /// missing).
    fn new(shell: Shell, routers: Option<Vec<String>>) -> Self {
        let locale = shell.locale();
        let rows = routers.map(|ids| {
            ids.into_iter()
                .map(|router| {
                    let title = tr(locale, keys::WEB_CONFIG_TITLE, None);
                    let link = Piece::link(format!("/ui/r/{router}/config"), title);
                    (router, Cell::of(vec![link]))
                })
                .collect()
        });
        Self {
            table: routers_table((locale, keys::WEB_CLIENTS_LANDING_PAGES), rows),
            shell,
        }
    }
}

/// `GET /ui/configuration`: the routers and their configuration pages.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Configuration, None)
        .await;
    let Some(fleet) = state.fleet() else {
        return errors::render(&Page::new(shell, None));
    };
    match fleet.visible(user.role()).await {
        Ok(entries) => errors::render(&Page::new(
            shell,
            Some(entries.into_iter().map(|entry| entry.profile.id).collect()),
        )),
        Err(error) => errors::internal(&error, shell),
    }
}
