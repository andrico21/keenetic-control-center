//! `GET /ui/advanced` (route table: `RawRci`): every router the user may read, with its
//! command explorer and its consoles.

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
#[template(path = "pages/advanced.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// One row per router: its id and its explorer and consoles.
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
                    let tools = [
                        ("explorer", keys::WEB_EXPLORER_TITLE),
                        ("console/rci", keys::WEB_CONSOLE_RCI_TITLE),
                        ("console/cli", keys::WEB_CONSOLE_CLI_TITLE),
                    ];
                    let mut span = Piece::span("tool-links", String::new());
                    for (index, (page, key)) in tools.into_iter().enumerate() {
                        if index > 0 {
                            span = span.with(Piece::text(" ".to_owned()));
                        }
                        let href = format!("/ui/r/{router}/{page}");
                        span = span.with(Piece::link(href, tr(locale, key, None)));
                    }
                    (router, Cell::of(vec![span]))
                })
                .collect()
        });
        Self {
            table: routers_table((locale, keys::WEB_EXPLORER_TOOLS), rows),
            shell,
        }
    }
}

/// `GET /ui/advanced`: the routers and their explorer and console links.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Advanced, None)
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
