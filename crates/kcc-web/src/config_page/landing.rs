//! `GET /ui/configuration` (route table: `Write`): every router the user may read, with
//! its configuration and backups page.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_i18n::keys;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::Caller,
};

/// The landing page.
#[derive(Template)]
#[template(path = "pages/config_landing.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Whether fleet services are attached.
    available: bool,
    /// Router profile ids.
    routers: Vec<String>,
}

localized!(Page);

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
            routers: entries.into_iter().map(|entry| entry.profile.id).collect(),
        }),
        Err(error) => errors::internal(&error, shell),
    }
}
