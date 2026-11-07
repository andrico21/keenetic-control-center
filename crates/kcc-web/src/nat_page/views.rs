//! The port forwarding page's tables: the forwarding rules and the interfaces with
//! address translation, each filtered, sorted and cut into pages of 50 rows.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_catalog::Catalog;
use kcc_domain::{
    DomainError, RouterCtx,
    nat::{descriptor::DESCRIPTOR, read},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::forwards::{Forward, forwards};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    clients_pages::{TabLink, rendered},
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    routing_page::frame::{Frame, Tab, Visit, view},
    system_pages::shared::with_query,
    table::rows::{Table, TableQuery},
};

/// The forwarding rules (`partials/nat_rules.html`).
#[derive(Template)]
#[template(path = "partials/nat_rules.html")]
pub(crate) struct RulesRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// Router profile id.
    router: String,
    /// The shown page of rules.
    table: Table<Forward>,
    /// Whether the role may remove rules.
    removable: bool,
}

impl Localize for RulesRegion {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl RulesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The address of the removal dialog of `rule`.
    fn remove_url(&self, rule: &Forward) -> String {
        let pairs = rule.pairs();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        with_query(
            &format!("/ui/r/{}/nat/forward/remove", self.router),
            &borrowed,
        )
    }

    /// The protocol of `rule` as people read it.
    fn protocol(&self, rule: &Forward) -> String {
        tr(
            self.shell.locale(),
            rule.protocol_label().unwrap_or(keys::WEB_NAT_ANY),
            None,
        )
    }

    /// The external ports of `rule` as people read them.
    fn ports(&self, rule: &Forward) -> String {
        match rule.ports() {
            None => tr(self.shell.locale(), keys::WEB_NAT_ANY, None),
            Some((first, None)) => first.to_string(),
            Some((first, Some(last))) => {
                let mut args = FluentArgs::new();
                args.set("first", first.to_string());
                args.set("last", last.to_string());
                tr(self.shell.locale(), keys::WEB_NAT_PORT_RANGE, Some(&args))
            }
        }
    }

    /// The target port of `rule` as people read it.
    fn target_port(&self, rule: &Forward) -> String {
        rule.to_port().map_or_else(
            || tr(self.shell.locale(), keys::WEB_NAT_SAME_PORT, None),
            |port| port.to_string(),
        )
    }
}

/// `GET /ui/r/{router}/nat`: the forwarding rules.
pub(crate) async fn rules(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Nat).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let mut frame = Frame::new(shell, &router, Tab::Nat)
        .with_views(keys::WEB_NAT_VIEWS, views(&router, View::Rules));
    let region = match reading {
        Ok((facts, domain)) => {
            let allowed = allows(&user, &router, facts.catalog(), "forward");
            if allowed {
                frame =
                    frame.with_add(format!("/ui/r/{router}/nat/forward/new"), keys::WEB_NAT_ADD);
            }
            rules_region(&domain, (&router, &query), (allowed, locale))
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// Whether `user` may run the NAT write `operation` on `router` with `catalog`.
pub(crate) fn allows(user: &CurrentUser, router: &str, catalog: &Catalog, operation: &str) -> bool {
    Controls::new(user.role(), router)
        .with_operations(DESCRIPTOR.write_ops, Some(catalog))
        .allows(operation)
}

/// The forwarding rules region on `router` for `query` in `locale`, with Remove when
/// `removable`.
///
/// # Errors
///
/// Returns why the router did not answer.
// cancel-safe: reads only.
pub(crate) async fn rules_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (removable, locale): (bool, Locale),
) -> Result<RulesRegion, MessageKey> {
    let rules = read::running_forwards(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    Ok(RulesRegion {
        shell: fragment_shell(locale),
        oob: false,
        router: router.to_owned(),
        table: Table::new(forwards(&rules), query, format!("/ui/r/{router}/nat")),
        removable,
    })
}

/// The message of a router that did not answer a read.
pub(crate) fn unreachable(error: &DomainError) -> MessageKey {
    tracing::warn!(%error, "port forwarding page: read failed");
    keys::WEB_KIT_UNREACHABLE
}

/// The page's views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum View {
    /// Forwarding rules.
    Rules,
    /// NAT interfaces.
    Interfaces,
    /// Active connections.
    Sessions,
}

/// The view switch on `router`, `shown` current.
pub(crate) fn views(router: &str, shown: View) -> Vec<TabLink> {
    [
        (View::Rules, "nat", keys::WEB_NAT_RULES),
        (View::Interfaces, "nat/interfaces", keys::WEB_NAT_INTERFACES),
        (View::Sessions, "nat/sessions", keys::WEB_NAT_SESSIONS),
    ]
    .into_iter()
    .map(|(each, tail, label)| view(format!("/ui/r/{router}/{tail}"), label, each == shown))
    .collect()
}
