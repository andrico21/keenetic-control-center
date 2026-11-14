//! `GET /ui/clients` (route table: `Read`): every router the user may read, with its
//! clients, DHCP and segments pages.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_i18n::{bundle::tr, keys};

use super::{Tab, TabLink};
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
#[template(path = "pages/clients_landing.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// One row per router: its id and its local network pages.
    table: TableView,
}

localized!(Page);

impl Page {
    /// The page in `shell` over `routers` (none while fleet services are missing): each
    /// router id and its local network pages.
    fn new(shell: Shell, routers: Option<Vec<(String, Vec<TabLink>)>>) -> Self {
        let locale = shell.locale();
        let rows = routers.map(|listed| {
            listed
                .into_iter()
                .map(|(router, links)| {
                    let mut span = Piece::span("tool-links", String::new());
                    for (index, link) in links.into_iter().enumerate() {
                        if index > 0 {
                            span = span.with(Piece::text(" ".to_owned()));
                        }
                        let label = tr(locale, link.label(), None);
                        span = span.with(Piece::link(link.href().to_owned(), label));
                    }
                    (router, Cell::of(vec![span]))
                })
                .collect()
        });
        Self {
            table: routers_table((locale, keys::WEB_CLIENTS_LANDING_PAGES), rows),
            shell,
        }
    }
}

/// `GET /ui/clients`: the routers and their local network pages.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Clients, None)
        .await;
    let Some(fleet) = state.fleet() else {
        return errors::render(&Page::new(shell, None));
    };
    match fleet.visible(user.role()).await {
        Ok(entries) => errors::render(&Page::new(
            shell,
            Some(
                entries
                    .into_iter()
                    .map(|entry| {
                        let links = Tab::Clients.links(&entry.profile.id);
                        (entry.profile.id, links)
                    })
                    .collect(),
            ),
        )),
        Err(error) => errors::internal(&error, shell),
    }
}
