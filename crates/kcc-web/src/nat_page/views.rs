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
    clients_pages::TabLink,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        gate::Controls,
        request::{rendered, with_query},
    },
    routing_page::frame::{Frame, Tab, Visit, view},
    table::{
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        rows::{Table, TableQuery},
        view::TableView,
    },
};

/// The forwarding rules (`partials/nat_rules.html`).
#[derive(Template)]
#[template(path = "partials/nat_rules.html")]
pub(crate) struct RulesRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// The shown page of rules.
    table: TableView,
}

localized!(RulesRegion);

impl RulesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }
}

/// The forwarding rules on `router`, with Remove where the NAT domain can express the
/// rule when `removable`, in `locale`.
fn rules_view(
    router: &str,
    table: &Table<Forward>,
    (removable, locale): (bool, Locale),
) -> TableView {
    let mut view = TableView::filtered(
        "table routing-table",
        table,
        (locale, keys::WEB_NAT_RULES_EMPTY),
    );
    for (column, key) in [
        ("ports", keys::WEB_NAT_COL_PORTS),
        ("protocol", keys::WEB_ROUTING_COL_PROTOCOL),
        ("interface", keys::WEB_NAT_COL_INTERFACE),
        ("target", keys::WEB_NAT_COL_TARGET),
        ("target_port", keys::WEB_NAT_COL_TARGET_PORT),
    ] {
        view = view.head(Head::sorted(tr(locale, key, None), table.header(column)));
    }
    if removable {
        view = view.head(Head::hidden(tr(locale, keys::WEB_CLIENTS_ACTIONS, None)));
    }
    for (index, rule) in table.rows().iter().enumerate() {
        let id = format!("forward-{}", index.saturating_add(1));
        let ports = match rule.ports() {
            None => tr(locale, keys::WEB_NAT_ANY, None),
            Some((first, None)) => first.to_string(),
            Some((first, Some(last))) => {
                let mut args = FluentArgs::new();
                args.set("first", first.to_string());
                args.set("last", last.to_string());
                tr(locale, keys::WEB_NAT_PORT_RANGE, Some(&args))
            }
        };
        let target_port = rule.to_port().map_or_else(
            || tr(locale, keys::WEB_NAT_SAME_PORT, None),
            |port| port.to_string(),
        );
        let protocol = rule.protocol_label().unwrap_or(keys::WEB_NAT_ANY);
        let mut cells = vec![
            Cell::code(ports).attr("id", id.clone()).head(),
            Cell::text(tr(locale, protocol, None)),
            Cell::code(rule.incoming().to_owned()),
            Cell::code(rule.target().to_owned()),
            Cell::code(target_port),
        ];
        if removable {
            let act = if rule.domain_rule().is_some() {
                let pairs = rule.pairs();
                let borrowed: Vec<(&str, &str)> = pairs
                    .iter()
                    .map(|(name, value)| (*name, value.as_str()))
                    .collect();
                let href = with_query(&format!("/ui/r/{router}/nat/forward/remove"), &borrowed);
                Act::opens(tr(locale, keys::WEB_ROUTING_REMOVE, None), href).danger()
            } else {
                Act::note(tr(locale, keys::WEB_NAT_EXPLORER_ONLY, None))
            };
            cells.push(Cell::acts(Layout::Block, vec![act], id).class("lan-actions"));
        }
        view = view.row(cells);
    }
    view
}

/// `GET /ui/r/{router}/nat`: the forwarding rules.
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn rules_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (removable, locale): (bool, Locale),
) -> Result<RulesRegion, MessageKey> {
    let rules = read::running_forwards(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    let table = Table::new(forwards(&rules), query, format!("/ui/r/{router}/nat"));
    Ok(RulesRegion {
        shell: fragment_shell(locale),
        oob: false,
        table: rules_view(router, &table, (removable, locale)),
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
