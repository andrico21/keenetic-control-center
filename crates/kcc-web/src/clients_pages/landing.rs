//! `GET /ui/clients` (route table: `Read`): every router the user may read, with its
//! clients, DHCP and segments pages.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_i18n::keys;

use super::{Tab, TabLink};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize, Shell},
    page_kit::context::Caller,
};

/// The landing page.
#[derive(Template)]
#[template(path = "pages/clients_landing.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Whether fleet services are attached.
    available: bool,
    /// One row per router: its id and its local network pages.
    routers: Vec<(String, Vec<TabLink>)>,
}

impl Localize for Page {
    fn shell(&self) -> &Shell {
        &self.shell
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
        return errors::render(&Page {
            shell,
            available: false,
            routers: Vec::new(),
        });
    };
    match fleet.visible(user.role()).await {
        Ok(entries) => errors::render(&Page {
            shell,
            available: true,
            routers: entries
                .into_iter()
                .map(|entry| {
                    let links = Tab::Clients.links(&entry.profile.id);
                    (entry.profile.id, links)
                })
                .collect(),
        }),
        Err(error) => errors::internal(&error, shell),
    }
}
