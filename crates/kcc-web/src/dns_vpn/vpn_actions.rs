//! The VPN row and panel actions: a connection on or off, a connection deleted after its
//! name is typed, a server's service on or off.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_catalog::Risk;
use kcc_domain::{
    vpn_clients::{self, VpnClientChange},
    vpn_servers::{self, VpnServerChange, VpnServerService},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    check,
    screen::{Answered, read_back},
    vpn_checks::Planned as Changes,
    vpn_pages::{Spot, region},
    vpn_read::exists,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::{Dialog, Resubmit, TypedNameForm},
        failure::plan_failure,
        family::Family,
        outcome::Outcome,
        request::{Params, missing, shown_query},
        respond::{self, Answer},
        submit::{self, Formless, Invalid, Planned, Submission},
    },
};

/// A connection on or off, audited as `web.vpn_state`.
const STATE: Operation = Operation::write(&vpn_clients::DESCRIPTOR, "enabled", "web.vpn_state");

/// A connection deleted, audited as `web.vpn_delete`.
const DELETE: Operation = Operation::write(&vpn_clients::DESCRIPTOR, "delete", "web.vpn_delete");

/// The connection a delete dialog names.
#[derive(Debug, Deserialize)]
pub(crate) struct TunnelQuery {
    /// The connection's name.
    #[serde(default)]
    tunnel: String,
}

/// `POST /ui/r/{router}/vpn/state`: turns the connection `tunnel` on (`enabled=on`) or off;
/// the fields may come in the query too, as the confirmation sends them again.
///
/// # Errors
///
/// Answers 404 for malformed fields, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
pub(crate) async fn switch(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let values = Params::new(query, pairs);
    let opened = STATE.open(&state, &user, &router).await?;
    let parsed = check::object(values.text("tunnel")).zip(on(&values));
    let (action, found) = match &parsed {
        Some((name, _)) => known(opened, name).await?,
        None => (opened, false),
    };
    let checked = parsed
        .filter(|_| found)
        .map(|(name, enabled)| Changes::Clients(vec![VpnClientChange::Enabled { name, enabled }]))
        .ok_or_else(|| Invalid::at("tunnel", keys::WEB_VPN_ERROR_NAME));
    let reply = Reply::new(&headers, &user, &router);
    let resubmit = Resubmit::new(
        values.again(&format!("/ui/r/{router}/vpn/state")),
        "#page-outcome",
    );
    Ok(run(
        Submission::new(action, &values, Formless, resubmit),
        checked,
        reply,
    )
    .await)
}

/// `POST /ui/r/{router}/vpn/service`: turns a VPN server's service on or off; the fields
/// may come in the query too, as the confirmation sends them again.
///
/// # Errors
///
/// Answers 404 for an unknown server, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
pub(crate) async fn service(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let values = Params::new(query, pairs);
    let (service, operation) = match values.text("service") {
        "vpn" => (VpnServerService::Vpn, "vpn_service"),
        "sstp" => (VpnServerService::Sstp, "sstp_service"),
        "oc" => (VpnServerService::OpenConnect, "openconnect_service"),
        "ipsec" => (VpnServerService::Ipsec, "ipsec_service"),
        _ => return Err(missing()),
    };
    let write = Operation::write(&vpn_servers::DESCRIPTOR, operation, "web.vpn_service");
    let action = write.open(&state, &user, &router).await?;
    let checked = on(&values)
        .map(|enabled| Changes::Servers(vec![VpnServerChange::Service { service, enabled }]))
        .ok_or_else(|| Invalid::at("enabled", keys::WEB_DNS_ERROR_CHOICE));
    let reply = Reply::new(&headers, &user, &router).reading(Spot::Servers);
    let resubmit = Resubmit::new(
        values.again(&format!("/ui/r/{router}/vpn/service")),
        "#page-outcome",
    );
    Ok(run(
        Submission::new(action, &values, Formless, resubmit),
        checked,
        reply,
    )
    .await)
}

/// `GET /ui/r/{router}/vpn/delete?tunnel=`: asks for the connection's name.
///
/// # Errors
///
/// Answers 404 for a malformed name, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TunnelQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let name = check::object(&query.tunnel).ok_or_else(missing)?;
    Ok(errors::render(&confirmation(
        action.locale(),
        &router,
        &name,
    )))
}

/// `POST /ui/r/{router}/vpn/delete`: deletes the connection once its name is typed.
///
/// # Errors
///
/// Answers the dialog again (422) when the typed name does not match, and what the kit
/// answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let opened = DELETE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let named = check::object(form.name());
    let (action, found) = match &named {
        Some(name) => known(opened, name).await?,
        None => (opened, false),
    };
    let dialog = DeleteForm(confirmation(
        locale,
        &router,
        named.as_deref().unwrap_or_default(),
    ));
    let checked = match named.filter(|_| found) {
        Some(name) if form.confirmed() => {
            Ok(Changes::Clients(vec![VpnClientChange::Delete { name }]))
        }
        Some(_) => Err(Invalid::at("confirm_name", keys::WEB_ADMIN_ERROR_CONFIRM)),
        None => Err(Invalid::at("name", keys::WEB_VPN_ERROR_NAME)),
    };
    let params = Params::of(Vec::new());
    let resubmit = Resubmit::new(format!("/ui/r/{router}/vpn/delete"), "#page-outcome");
    let submission = Submission::new(action, &params, dialog, resubmit)
        .confirmed_by_page(Risk::Destructive)
        .landing_in("#page-outcome");
    let reply = Reply::new(&headers, &user, &router);
    Ok(run(submission, checked, reply).await)
}

/// `action` again, and whether `name` is one of the router's VPN connections.
///
/// These routes never switch or delete another interface.
///
/// # Errors
///
/// Answers the audited failure when the connections cannot be read.
// NOT cancel-safe: an abandoned append may still be written.
async fn known<'call>(action: Action<'call>, name: &str) -> Result<(Action<'call>, bool), Answer> {
    let locale = action.locale();
    let ctx = action.context().await?;
    match exists(&ctx, name).await {
        Ok(found) => Ok((action, found)),
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            Err(Answered::new(Outcome::failed(failure), locale)
                .respond()
                .into())
        }
    }
}

/// The typed-name confirmation, as the form of the deletion: a mistyped name is shown in
/// it, a connection the router does not have is 404.
struct DeleteForm(Dialog);

impl submit::Form for DeleteForm {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let Self(mut dialog) = self;
        for (field, rule) in invalid.into_findings() {
            if field != "confirm_name" {
                return missing().into_response();
            }
            dialog.set_error(tr(locale, rule, None));
        }
        respond::in_dialog(respond::unprocessable(&dialog))
    }
}

/// The typed-name confirmation deleting the connection `name` of `router`.
fn confirmation(locale: Locale, router: &str, name: &str) -> Dialog {
    Dialog::typed_name(
        locale,
        format!("/ui/r/{router}/vpn/delete"),
        name,
        (keys::WEB_VPN_DELETE_TITLE, keys::WEB_VPN_DELETE_TEXT),
    )
}

/// The field `enabled`: `on` or `off`.
fn on(values: &Params) -> Option<bool> {
    match values.text("enabled") {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// Where an action's answer goes: the page that sent it, its user and router, and the
/// region to read back.
struct Reply<'request> {
    /// Request headers, for the page's table query.
    headers: &'request HeaderMap,
    /// The signed-in user.
    user: &'request CurrentUser,
    /// Router profile id.
    router: &'request str,
    /// The region read back.
    spot: Spot,
}

impl<'request> Reply<'request> {
    /// The answer to `user` on the page of `headers` about `router`, reading the
    /// connections back.
    const fn new(
        headers: &'request HeaderMap,
        user: &'request CurrentUser,
        router: &'request str,
    ) -> Self {
        Self {
            headers,
            user,
            router,
            spot: Spot::Connections,
        }
    }

    /// Reads `spot` back instead.
    fn reading(mut self, spot: Spot) -> Self {
        self.spot = spot;
        self
    }
}

/// Plans the `checked` changes for `submission`, runs them and answers as `reply` says.
// NOT cancel-safe: see `Submission::submit`.
async fn run<F>(
    submission: Submission<'_, F>,
    checked: Result<Changes, Invalid>,
    reply: Reply<'_>,
) -> Response
where
    F: submit::Form,
{
    submission
        .submit(
            |_values| checked,
            async |changes, ctx| {
                let (operation, request) = changes.request(ctx).await?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| {
                let viewer = reply
                    .spot
                    .viewer(ctx, reply.user, reply.router)
                    .with_table_query(shown_query(reply.headers));
                read_back(region(ctx, &reply.spot, &viewer).await)
            },
        )
        .await
}
