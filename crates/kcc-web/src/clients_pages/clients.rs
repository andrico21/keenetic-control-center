//! `GET /ui/r/{router}/clients`: the clients the router reports, filtered by state,
//! connection and text, sorted and paged, with the row actions the role may run.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::clients;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    Tab, TabLink,
    client_view::{FilterQuery, Region, View},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller},
        family::Family,
        gate::Controls,
    },
    table::rows::TableQuery,
};

/// The clients page.
#[derive(Template)]
#[template(path = "pages/clients.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The local network tabs.
    tabs: Vec<TabLink>,
    /// The filter form and the table, when the router answered.
    region: Option<Region>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
}

localized!(Page);

/// `GET /ui/r/{router}/clients`: the table and the controls the role may use.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    Query(filters): Query<FilterQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Clients, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tab::Clients.links(&router),
        router: router.clone(),
        region: None,
        problem: None,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => match clients::read_clients(&domain).await {
            Ok(list) => {
                let controls = Controls::new(user.role(), &router)
                    .with_operations(clients::DESCRIPTOR.write_ops, Some(facts.catalog()));
                let region = View::new(query, &filters).region(user.locale(), router, list);
                page.region = Some(region.with_controls(controls));
            }
            Err(error) => {
                tracing::warn!(%error, "clients page: the client list could not be read");
                page.problem = Some(keys::WEB_CLIENTS_READ_ERROR);
            }
        },
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}
