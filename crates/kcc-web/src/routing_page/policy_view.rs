//! The connection policies view: one filtered, sorted table of policies with their
//! interfaces in order and multipath, and the row actions the role may use.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, policies::descriptor::DESCRIPTOR};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{
    frame::{Frame, Tab, Visit},
    policy_rows::read_policies,
    tables::policies_view,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls, request::rendered},
    table::{
        rows::{Table, TableQuery},
        view::TableView,
    },
};

/// The policies table (`partials/routing_policies.html`).
#[derive(Template)]
#[template(path = "partials/routing_policies.html")]
pub(crate) struct PoliciesRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// The shown page of policies.
    table: TableView,
}

localized!(PoliciesRegion);

impl PoliciesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}

/// `GET /ui/r/{router}/routing/policies`: the connection policies.
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Policies).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let mut frame = Frame::new(shell, &router, Tab::Policies);
    let region = match reading {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(DESCRIPTOR.write_ops, Some(facts.catalog()));
            if controls.allows("policy") {
                let href = format!("/ui/r/{router}/routing/policy/new");
                frame = frame.with_add(href, keys::WEB_ROUTING_POLICY_ADD);
            }
            policies_region(&domain, (&router, &query), (controls, locale))
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The policies region on `router` for `query`, with the row actions `controls` allow,
/// in `locale`.
///
/// # Errors
///
/// Returns why the router did not answer.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn policies_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (controls, locale): (Controls, Locale),
) -> Result<PoliciesRegion, MessageKey> {
    let policies = read_policies(domain).await?;
    let table = Table::new(policies, query, format!("/ui/r/{router}/routing/policies"));
    Ok(PoliciesRegion {
        shell: fragment_shell(locale),
        oob: false,
        table: policies_view(router, &table, (&controls, locale)),
    })
}
