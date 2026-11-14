//! The KeenDNS management changes: the remote access level and web proxy entries.
//!
//! Both change how the router and the home network are reached from outside: they need
//! `Destructive` too and run inside the fail-safe timer. The access buttons ask with the
//! kit's dialog; the proxy dialog explains the timer itself and its Apply confirms, and
//! the server checks either way.

use core::net::Ipv4Addr;

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::keendns::{self, RemoteSecurityLevel};
use kcc_i18n::keys;

use super::{
    keendns::Viewer,
    keendns_forms::{NameDialog, PROTOCOLS, is_label, planned},
    shared::{NoDialog, merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        confirm::Resubmit,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Invalid, Submission},
    },
};

/// Setting the remote access level, audited as `web.keendns_access`.
const ACCESS: Operation = Operation::write(
    &keendns::DESCRIPTOR,
    "cloud_security_level",
    "web.keendns_access",
);

/// Adding a web proxy entry, audited as `web.keendns_proxy`.
const PROXY: Operation =
    Operation::write(&keendns::DESCRIPTOR, "proxy_upstream", "web.keendns_proxy");

/// `POST /ui/r/{router}/system/keendns/access?level=public|private`: sets who may reach
/// the router's web interface through KeenDNS; asks first.
///
/// # Errors
///
/// Answers 404 for an unknown level, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn access(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let (word, level) = match value(&pairs, "level") {
        Some("public") => ("public", RemoteSecurityLevel::Public),
        Some("private") => ("private", RemoteSecurityLevel::Private),
        Some(_) | None => return Err(missing()),
    };
    let action = ACCESS.open(&state, &user, &router).await?;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/keendns/access"),
            &[("level", word)],
        ),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router);
    Ok(Submission::new(action, &Params::of(pairs), NoDialog)
        .confirming(Risk::Management, resubmit)
        .submit(
            |_params| Ok(()),
            async |(), domain| planned(keendns::plan_cloud_security_level(domain, level)?),
            async |domain| viewer.refreshed(domain).await,
        )
        .await)
}

/// `GET /ui/r/{router}/system/keendns/proxy`: the proxy-entry dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn proxy_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = PROXY.open(&state, &user, &router).await?;
    let dialog = NameDialog::new(&router, action.locale(), true).filled([
        String::new(),
        "http".to_owned(),
        String::new(),
        "80".to_owned(),
    ]);
    Ok(dialog.show())
}

/// `POST /ui/r/{router}/system/keendns/proxy`: publishes a home device under the KeenDNS
/// name; a management change.
///
/// # Errors
///
/// Answers the dialog with its error (422), and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn proxy(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = PROXY.open(&state, &user, &router).await?;
    let fields = ["name", "protocol", "host", "port"]
        .map(|name| value(&pairs, name).unwrap_or_default().to_owned());
    let dialog = NameDialog::new(&router, action.locale(), true).filled(fields.clone());
    let [name, protocol, host, port] = fields;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/keendns/proxy"),
            &[
                ("name", &name),
                ("protocol", &protocol),
                ("host", &host),
                ("port", &port),
            ],
        ),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router);
    Ok(Submission::new(action, &Params::of(pairs), dialog)
        .confirming(Risk::Management, resubmit)
        .submit(
            |_params| {
                let valid = is_label(&name)
                    && PROTOCOLS.contains(&protocol.as_str())
                    && host.parse::<Ipv4Addr>().is_ok();
                port.parse::<u16>()
                    .ok()
                    .filter(|number| *number > 0 && valid)
                    .ok_or_else(|| Invalid::at("name", keys::WEB_SYSTEM_KEENDNS_PROXY_ERROR))
            },
            async |number, domain| {
                planned(keendns::plan_proxy_upstream(
                    domain, &name, &protocol, &host, number,
                )?)
            },
            async |domain| viewer.refreshed(domain).await,
        )
        .await)
}
