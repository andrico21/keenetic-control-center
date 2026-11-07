//! The firewall page's views: the access lists, the lists applied to interfaces, and the
//! UPnP redirects.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    firewall::{descriptor::DESCRIPTOR, read},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{
    lists_region::ListsRegion,
    regions::{BindingsRegion, Redirect, UpnpRegion},
    snapshot::{self, Snapshot},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    clients_pages::{TabLink, rendered},
    page_kit::{context::fragment_shell, gate::Controls},
    routing_page::frame::{Frame, Tab, Visit, view},
    system_pages::shared::shown_query,
    table::rows::{Table, TableQuery},
};

/// The region a change reads back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spot {
    /// The access lists.
    Lists,
    /// The lists applied to interfaces.
    Bindings,
}

/// The region of the page that sent a request: the bindings when the browser shows the
/// interfaces view (htmx's `HX-Current-URL`), the access lists otherwise.
pub(crate) fn spot_of(headers: &HeaderMap) -> Spot {
    let shown = headers
        .get("hx-current-url")
        .and_then(|found| found.to_str().ok())
        .unwrap_or_default();
    let path = shown.split(['?', '#']).next().unwrap_or_default();
    if path.ends_with("/firewall/interfaces") {
        Spot::Bindings
    } else {
        Spot::Lists
    }
}

/// What the role may change on the router: rules, and which list applies where.
pub(crate) fn controls(user: &CurrentUser, router: &str, catalog: &Catalog) -> (bool, bool) {
    let allowed =
        Controls::new(user.role(), router).with_operations(DESCRIPTOR.write_ops, Some(catalog));
    (allowed.allows("rule"), allowed.allows("binding"))
}

/// `GET /ui/r/{router}/firewall`: the access lists.
pub(crate) async fn lists(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Firewall).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let mut frame = Frame::new(shell, &router, Tab::Firewall)
        .with_views(keys::WEB_FIREWALL_VIEWS, views(&router, Spot::Lists, false));
    let region = match reading {
        Ok((facts, domain)) => {
            let allowed = controls(&user, &router, facts.catalog());
            if allowed.0 {
                frame = frame.with_add(
                    format!("/ui/r/{router}/firewall/rule/new"),
                    keys::WEB_FIREWALL_ADD,
                );
            }
            lists_region(&domain, &router, allowed, locale)
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// `GET /ui/r/{router}/firewall/interfaces`: the lists applied to interfaces.
pub(crate) async fn bindings(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Firewall).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let mut frame = Frame::new(shell, &router, Tab::Firewall).with_views(
        keys::WEB_FIREWALL_VIEWS,
        views(&router, Spot::Bindings, false),
    );
    let region = match reading {
        Ok((facts, domain)) => {
            let (_, bind) = controls(&user, &router, facts.catalog());
            if bind {
                frame = frame.with_add(
                    format!("/ui/r/{router}/firewall/bind"),
                    keys::WEB_FIREWALL_BIND,
                );
            }
            bindings_region(&domain, (&router, &query), bind, locale)
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// `GET /ui/r/{router}/firewall/upnp`: the UPnP redirects, read only.
pub(crate) async fn upnp(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Firewall).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let frame = Frame::new(shell, &router, Tab::Firewall)
        .with_views(keys::WEB_FIREWALL_VIEWS, views(&router, Spot::Lists, true));
    let region = match reading {
        Ok((_facts, domain)) => match read::upnp_redirects(&domain).await {
            Ok(rows) => {
                let shown = rows.iter().map(Redirect::new).collect();
                let table = Table::new(shown, &query, format!("/ui/r/{router}/firewall/upnp"));
                Ok(rendered(&UpnpRegion::new(fragment_shell(locale), table)))
            }
            Err(error) => {
                tracing::warn!(%error, "firewall page: UPnP redirects unavailable");
                Err(keys::WEB_KIT_UNREACHABLE)
            }
        },
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The access lists region on `router` with the `(rules, bind)` controls, in `locale`.
///
/// # Errors
///
/// Returns why the configuration could not be read.
// cancel-safe: reads only.
pub(crate) async fn lists_region(
    domain: &RouterCtx,
    router: &str,
    allowed: (bool, bool),
    locale: Locale,
) -> Result<ListsRegion, MessageKey> {
    let firewall = snapshot::read(domain).await?;
    Ok(lists_of(&firewall, (router, domain), allowed, locale))
}

/// The access lists region of `firewall`.
fn lists_of(
    firewall: &Snapshot,
    (router, domain): (&str, &RouterCtx),
    allowed: (bool, bool),
    locale: Locale,
) -> ListsRegion {
    let ipv6 = read::ipv6_available(domain).then(|| firewall.ipv6().to_vec());
    ListsRegion::new(
        (fragment_shell(locale), router.to_owned()),
        (
            firewall.lists().to_vec(),
            firewall.bindings().to_vec(),
            ipv6,
        ),
        allowed,
    )
}

/// The bindings region on `router` for `query`, with Remove when `removable`, in
/// `locale`.
///
/// # Errors
///
/// Returns why the configuration could not be read.
// cancel-safe: reads only.
pub(crate) async fn bindings_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    removable: bool,
    locale: Locale,
) -> Result<BindingsRegion, MessageKey> {
    let firewall = snapshot::read(domain).await?;
    let table = Table::new(
        firewall.bindings().to_vec(),
        query,
        format!("/ui/r/{router}/firewall/interfaces"),
    );
    Ok(BindingsRegion::new(
        fragment_shell(locale),
        router.to_owned(),
        (table, removable),
    ))
}

/// The `spot` region read back for `user` on the page of `headers`, out of band.
// cancel-safe: reads only.
pub(crate) async fn refreshed(
    domain: &RouterCtx,
    (router, user): (&str, &CurrentUser),
    (spot, headers): (Spot, &HeaderMap),
    locale: Locale,
) -> Option<String> {
    let allowed = controls(user, router, &domain.catalog);
    match spot {
        Spot::Lists => lists_region(domain, router, allowed, locale)
            .await
            .ok()
            .and_then(|region| rendered(&region.out_of_band())),
        Spot::Bindings => {
            bindings_region(domain, (router, &shown_query(headers)), allowed.1, locale)
                .await
                .ok()
                .and_then(|region| rendered(&region.out_of_band()))
        }
    }
}

/// The view switch on `router`: `shown` current, or the UPnP view when `upnp`.
fn views(router: &str, shown: Spot, upnp: bool) -> Vec<TabLink> {
    vec![
        view(
            format!("/ui/r/{router}/firewall"),
            keys::WEB_FIREWALL_LISTS,
            !upnp && shown == Spot::Lists,
        ),
        view(
            format!("/ui/r/{router}/firewall/interfaces"),
            keys::WEB_FIREWALL_BINDINGS,
            !upnp && shown == Spot::Bindings,
        ),
        view(
            format!("/ui/r/{router}/firewall/upnp"),
            keys::WEB_FIREWALL_UPNP,
            upnp,
        ),
    ]
}
