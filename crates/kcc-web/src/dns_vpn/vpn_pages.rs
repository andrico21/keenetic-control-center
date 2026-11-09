//! The VPN pages at `/ui/r/{router}/vpn`: the connections and servers tabs, a WireGuard
//! connection's peers, the dialogs and their changes.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{OperationDescriptor, RouterCtx, vpn_clients, vpn_servers};
use kcc_i18n::{bundle::tr, keys};

use super::{
    cells::Act,
    check,
    flow::{self, Closed, Viewer, Visit},
    form::Values,
    region::Region,
    screen::{Page, Tab, missing},
    vpn_forms::VpnForm,
    vpn_peer_psk::{self, PeerKey},
    vpn_read::{exists, free_wireguard},
    vpn_servers_tab, vpn_tabs,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    page_kit::{
        context::Caller,
        failure::plan_failure,
        family::Family,
        gate::Controls,
        outcome::Outcome,
        respond::{self, Answer},
    },
    table::rows::TableQuery,
};

/// Which VPN region a request shows or reads back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Spot {
    /// The connections tab.
    Connections,
    /// The peers of one WireGuard connection.
    Peers(String),
    /// The servers tab.
    Servers,
}

impl Spot {
    /// The domain writes the region's controls come from.
    pub(crate) const fn operations(&self) -> &'static [OperationDescriptor] {
        match self {
            Self::Connections | Self::Peers(_) => vpn_clients::DESCRIPTOR.write_ops,
            Self::Servers => vpn_servers::DESCRIPTOR.write_ops,
        }
    }

    /// Who views the region on `router` after a change through `ctx`.
    pub(crate) fn viewer(&self, ctx: &RouterCtx, user: &CurrentUser, router: &str) -> Viewer {
        let controls = Controls::new(user.role(), router)
            .with_operations(self.operations(), Some(&ctx.catalog));
        Viewer::new(router, user.locale(), controls)
    }
}

/// `GET /ui/r/{router}/vpn`: the connections tab.
pub(crate) async fn connections(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    show(
        Visit::new(&state, &user, &router).with_query(query),
        caller,
        Spot::Connections,
    )
    .await
}

/// `GET /ui/r/{router}/vpn/servers`: the servers tab.
pub(crate) async fn servers(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    show(Visit::new(&state, &user, &router), caller, Spot::Servers).await
}

/// `GET /ui/r/{router}/vpn/peers/{tunnel}`: the peers of a WireGuard connection.
pub(crate) async fn peers(
    State(state): State<WebState>,
    Path((router, tunnel)): Path<(String, String)>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    let visit = Visit::new(&state, &user, &router).with_query(query);
    match check::tunnel(&tunnel) {
        Some(name) => show(visit, caller, Spot::Peers(name)).await,
        None => errors::response(Kind::NotFound, visit.shell(caller, Tab::Connections).await),
    }
}

/// The page of `spot`.
// cancel-safe: reads only.
async fn show(visit: Visit<'_>, caller: Caller<'_>, spot: Spot) -> Response {
    let tab = match spot {
        Spot::Connections | Spot::Peers(_) => Tab::Connections,
        Spot::Servers => Tab::VpnServers,
    };
    let shell = visit.shell(caller, tab).await;
    let locale = visit.locale();
    let router = visit.router().to_owned();
    let (region, actions) = match visit.open(spot.operations()).await {
        Ok((ctx, viewer)) => region(&ctx, &spot, &viewer).await,
        Err(Closed::Refused(refusal)) => return refusal.page(shell),
        Err(Closed::Unreadable(reason)) => (Region::failed(locale, reason), Vec::new()),
    };
    let page = Page::new(shell, (router.clone(), tab), region).with_actions(actions);
    errors::render(&match spot {
        Spot::Peers(name) => {
            let mut args = FluentArgs::new();
            args.set("name", name);
            let back = Act::link(locale, keys::WEB_VPN_BACK, format!("/ui/r/{router}/vpn"));
            page.titled(tr(locale, keys::WEB_VPN_PEERS_TITLE, Some(&args)))
                .with_back(back)
        }
        Spot::Connections | Spot::Servers => page,
    })
}

/// The region of `spot` and its page actions, read from the router of `ctx`.
// cancel-safe: reads only.
pub(crate) async fn region(ctx: &RouterCtx, spot: &Spot, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let failed = |error| {
        let failure = plan_failure(Family::Changes, locale, &error);
        (
            Region::failed(locale, failure.message().to_owned()),
            Vec::new(),
        )
    };
    match spot {
        Spot::Servers => match vpn_servers::read_servers(ctx).await {
            Ok(status) => vpn_servers_tab::servers(&status, viewer),
            Err(error) => failed(error),
        },
        Spot::Connections => match vpn_clients::read_clients(ctx).await {
            Ok(clients) => vpn_tabs::connections(&clients, viewer),
            Err(error) => failed(error),
        },
        Spot::Peers(name) => match vpn_clients::read_clients(ctx).await {
            Ok(clients) => {
                let found = clients
                    .iter()
                    .find(|client| &client.id == name && client.wireguard.is_some());
                found.map_or_else(
                    || {
                        let mut args = FluentArgs::new();
                        args.set("name", name.clone());
                        let reason = tr(locale, keys::WEB_VPN_NO_TUNNEL, Some(&args));
                        (Region::failed(locale, reason), Vec::new())
                    },
                    |client| vpn_tabs::peers(client, viewer),
                )
            }
            Err(error) => failed(error),
        },
    }
}

/// `GET /ui/r/{router}/vpn/form/{form}`: a VPN dialog; the query fills its fields, and a
/// new connection's name defaults to the first free `Wireguard<N>`.
///
/// # Errors
///
/// Answers 404 for a dialog the page does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(mut prefill): Query<Vec<(String, String)>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let form = VpnForm::from_slug(&slug, &Values::new(prefill.clone())).ok_or_else(missing)?;
    let action = form.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    if matches!(form, VpnForm::Create | VpnForm::Import) {
        let ctx = action.context().await?;
        match vpn_clients::read_clients(&ctx).await {
            Ok(clients) => prefill.push(("name".to_owned(), free_wireguard(&clients))),
            Err(error) => {
                let failure = plan_failure(Family::Changes, locale, &error);
                let shown = Outcome::failed(failure).render(locale);
                return Err(respond::retarget(shown, "#page-outcome").into());
            }
        }
    }
    Ok(form
        .dialog(&router, locale)
        .values(&Values::new(prefill))
        .show())
}

/// `POST /ui/r/{router}/vpn/form/{form}`: checks the values, plans the changes with the
/// VPN domains, runs them and answers with the outcome and the region read back.
///
/// A peer's preshared key is taken out of the form first and written with the peer.
///
/// # Errors
///
/// Answers the dialog with its errors (422) when a value is invalid, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn submit(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(mut pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let psk = vpn_peer_psk::typed(&mut pairs);
    let values = Values::new(pairs);
    let form = VpnForm::from_slug(&slug, &values)
        .filter(|found| *found != VpnForm::Import)
        .ok_or_else(missing)?;
    let action = form.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    let dialog = || form.dialog(&router, locale).values(&values);
    let key_problems = vpn_peer_psk::problems(psk.as_ref().filter(|_| form == VpnForm::Peer));
    let planned = match (form.check(&values), key_problems.is_empty()) {
        (Ok(planned), true) => planned,
        (Ok(_), false) => {
            action.abandon("validation_failed").await;
            return Err(dialog().errors(&key_problems).invalid().into());
        }
        (Err(mut problems), _) => {
            problems.extend(key_problems);
            action.abandon("validation_failed").await;
            return Err(dialog().errors(&problems).invalid().into());
        }
    };
    let ctx = action.context().await?;
    // A new connection never reuses a name: that would regenerate a live tunnel's key.
    let taken = match form {
        VpnForm::Create => exists(&ctx, values.get("name").trim()).await,
        VpnForm::Import | VpnForm::Peer | VpnForm::Pool(_) | VpnForm::Dns(_) | VpnForm::Ipsec => {
            Ok(false)
        }
    };
    let peer_key = psk
        .filter(|_| form == VpnForm::Peer)
        .map(|key| PeerKey::new(&values, key));
    let written = planned.request(&ctx).and_then(|request| match peer_key {
        Some(key) => key.joined(request, &ctx),
        None => Ok(request),
    });
    let request = match taken.and_then(|used| Ok((used, written?))) {
        Ok((false, request)) => request,
        Ok((true, _)) => {
            action.abandon("validation_failed").await;
            let taken_name = vec![("name", keys::WEB_VPN_ERROR_NAME_TAKEN)];
            return Err(dialog().errors(&taken_name).invalid().into());
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon("validation_failed").await;
            return Err(dialog()
                .problem(failure.message().to_owned())
                .invalid()
                .into());
        }
    };
    let spot = match form {
        VpnForm::Peer => Spot::Peers(values.get("tunnel").trim().to_owned()),
        VpnForm::Create | VpnForm::Import => Spot::Connections,
        VpnForm::Pool(_) | VpnForm::Dns(_) | VpnForm::Ipsec => Spot::Servers,
    };
    let viewer = spot
        .viewer(&ctx, &user, &router)
        .with_query(flow::shown_query(&headers));
    let answered = flow::apply(action, request, async || region(&ctx, &spot, &viewer).await);
    Ok(answered.await.respond())
}
