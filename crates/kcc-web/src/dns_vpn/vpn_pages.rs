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
    check,
    flow::{Closed, Viewer, Visit},
    region::Region,
    screen::{Page, Tab, read_back},
    vpn_forms::VpnForm,
    vpn_peer_psk,
    vpn_peer_psk::PeerKey,
    vpn_read::{exists, free_wireguard},
    vpn_servers_tab, vpn_tabs,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    page_kit::{
        change::Change,
        confirm::Resubmit,
        context::Caller,
        failure::plan_failure,
        family::Family,
        gate::Controls,
        outcome::Outcome,
        read_failure::domain_problem,
        request::{Params, missing, shown_query},
        respond::{self, Answer},
        submit::{Invalid, Planned, Submission},
    },
    table::{acts::Act, rows::TableQuery},
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
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
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
        Visit::new(&state, &user, &router).with_table_query(query),
        caller,
        Spot::Connections,
    )
    .await
}

/// `GET /ui/r/{router}/vpn/servers`: the servers tab.
// NOT cancel-safe: it only reads router state to render the region, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
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
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn peers(
    State(state): State<WebState>,
    Path((router, tunnel)): Path<(String, String)>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    let visit = Visit::new(&state, &user, &router).with_table_query(query);
    match check::tunnel(&tunnel) {
        Some(name) => show(visit, caller, Spot::Peers(name)).await,
        None => errors::response(Kind::NotFound, visit.shell(caller, Tab::Connections).await),
    }
}

/// The page of `spot`.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
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
        Err(Closed::Unreadable(problem)) => (Region::unread(locale, &problem), Vec::new()),
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn region(ctx: &RouterCtx, spot: &Spot, viewer: &Viewer) -> (Region, Vec<Act>) {
    let locale = viewer.locale();
    let failed = |error| (Region::unread(locale, &domain_problem(&error)), Vec::new());
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
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(mut prefill): Query<Vec<(String, String)>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let form = VpnForm::from_slug(&slug, &Params::of(prefill.clone())).ok_or_else(missing)?;
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
        .values(&Params::of(prefill))
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
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
pub(crate) async fn submit(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(mut pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let psk = vpn_peer_psk::typed(&mut pairs);
    let values = Params::of(pairs);
    let form = VpnForm::from_slug(&slug, &values)
        .filter(|found| *found != VpnForm::Import)
        .ok_or_else(missing)?;
    let action = form.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    let key_problems = vpn_peer_psk::problems(psk.as_ref().filter(|_| form == VpnForm::Peer));
    let typed = match (form.check(&values), key_problems.is_empty()) {
        (Ok(changes), true) => Ok(changes),
        (Ok(_), false) => Err(key_problems),
        (Err(mut problems), _) => {
            problems.extend(key_problems);
            Err(problems)
        }
    };
    // A new connection never reuses a name: that would regenerate a live tunnel's key.
    let taken = match form {
        VpnForm::Create if typed.is_ok() => {
            exists(&action.context().await?, values.text("name").trim()).await
        }
        VpnForm::Create
        | VpnForm::Import
        | VpnForm::Peer
        | VpnForm::Pool(_)
        | VpnForm::Dns(_)
        | VpnForm::Ipsec => Ok(false),
    };
    let (checked, unread) = match taken {
        Ok(true) => (Err(vec![("name", keys::WEB_VPN_ERROR_NAME_TAKEN)]), None),
        Ok(false) => (typed, None),
        Err(error) => (typed, Some(error)),
    };
    let peer_key = psk
        .filter(|_| form == VpnForm::Peer)
        .map(|key| PeerKey::new(&values, key));
    let spot = match form {
        VpnForm::Peer => Spot::Peers(values.text("tunnel").trim().to_owned()),
        VpnForm::Create | VpnForm::Import => Spot::Connections,
        VpnForm::Pool(_) | VpnForm::Dns(_) | VpnForm::Ipsec => Spot::Servers,
    };
    let dialog = form.dialog(&router, locale).values(&values);
    let resubmit = Resubmit::new(format!("/ui/r/{router}/vpn/form/{slug}"), "#page-outcome");
    Ok(Submission::new(action, &values, dialog, resubmit)
        .submit(
            |_values| checked.map_err(Invalid::from),
            async |changes, ctx| {
                if let Some(error) = unread {
                    return Err(error);
                }
                let (operation, request) = changes.request(ctx).await?;
                let joined = match peer_key {
                    Some(key) => key.joined(request, ctx)?,
                    None => request,
                };
                Ok(Planned::of(&[operation], Change::Cli(joined)))
            },
            async |ctx| {
                let viewer = spot
                    .viewer(ctx, &user, &router)
                    .with_table_query(shown_query(&headers));
                read_back(region(ctx, &spot, &viewer).await)
            },
        )
        .await)
}
