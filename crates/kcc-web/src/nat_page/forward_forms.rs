//! Forward a port: the dialog, its checks, the plan and the read-back.
//!
//! A rule names a protocol (or none for every protocol), the incoming interface, an
//! external port or range (or none for every port), the device to forward to (an IPv4
//! address or the MAC address of a registered device) and the port there.

use core::{net::Ipv4Addr, str::FromStr as _};

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::workflow::WorkflowError;
use kcc_domain::{
    ChangeOp, RouterCtx,
    nat::{change, descriptor::DESCRIPTOR, read},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::Mac;

use super::{
    forwards::{Forward, PROTOCOLS, forwards, has_ports},
    views::{RulesRegion, rules_region},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    page_kit::{
        action::Operation,
        change::Applied,
        confirm::Resubmit,
        form::{Choice, FormDialog, Input},
        request::{Params, rendered, shown_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
        values,
    },
    routing_page::{
        frame::interface_names,
        reply::{Replying, refused, unread},
    },
};

/// A rule added, audited as `web.nat_forward_add`.
const ADD: Operation = Operation::write(&DESCRIPTOR, "forward", "web.nat_forward_add");

/// `GET /ui/r/{router}/nat/forward/new`: the Forward a port dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = ADD.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let names = interface_names(&domain)
        .await
        .map_err(|message| unusable(action.locale(), message))?;
    Ok(form(action.locale(), &router, &Params::default(), &names).show())
}

/// `POST /ui/r/{router}/nat/forward/new`: checks the rule, adds it and reads it back.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn add(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = ADD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let names = match interface_names(&action.context().await?).await {
        Ok(found) => found,
        Err(message) => return Ok(refused(action, unread(locale, message)).await),
    };
    let values = Params::new(Vec::new(), pairs);
    let dialog = Replying::new(form(locale, &router, &values, &names));
    let resubmit = Resubmit::new(format!("/ui/r/{router}/nat/forward/new"), "#page-outcome");
    Ok(Submission::new(action, &values, dialog, resubmit)
        .submit_reading(
            async |submitted, domain| {
                let rule =
                    check(submitted, &names).map_err(|(field, rule)| Invalid::at(field, rule))?;
                let planned = rule
                    .domain_rule()
                    .ok_or_else(|| Invalid::at("target", keys::WEB_NAT_ERROR_TARGET))?;
                let known = read::running_forwards(domain)
                    .await
                    .map_err(|_error| unread(locale, keys::WEB_KIT_UNREACHABLE))?;
                if forwards(&known).contains(&rule) {
                    return Err(Invalid::at("port", keys::WEB_ROUTING_ERROR_DUPLICATE).into());
                }
                Ok(planned)
            },
            async |planned, domain| Ok(applied(change::plan_add_forward(domain, &planned)?)),
            async |domain| rules(domain, &router, &headers, locale).await,
        )
        .await)
}

/// The NAT change `op`, run and read back by the NAT domain.
pub(crate) fn applied(op: ChangeOp) -> Planned {
    let operations = [op.clone()];
    Planned::working(&operations, move |changes, context| {
        Box::pin(async move {
            change::apply(changes, context, &op)
                .await
                .map(|result| Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                })
                .map_err(WorkflowError::from)
        })
    })
}

/// The rules region of `router` read back for the page of `headers`, out of band.
// cancel-safe: reads only.
pub(crate) async fn rules(
    domain: &RouterCtx,
    router: &str,
    headers: &HeaderMap,
    locale: Locale,
) -> Option<String> {
    rules_region(domain, (router, &shown_query(headers)), (true, locale))
        .await
        .ok()
        .map(RulesRegion::out_of_band)
        .and_then(|region| rendered(&region))
}

/// The rule the dialog describes.
///
/// # Errors
///
/// Returns the field to correct and why.
fn check(values: &Params, names: &[String]) -> Result<Forward, (&'static str, MessageKey)> {
    let text = |name: &str| values.text(name).trim().to_owned();
    let protocol = Some(text("protocol")).filter(|value| !value.is_empty());
    if protocol
        .as_deref()
        .is_some_and(|name| !PROTOCOLS.iter().any(|(known, _)| *known == name))
    {
        return Err(("protocol", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let interface = text("interface");
    if !names.contains(&interface) {
        return Err(("interface", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let port = values::port(&text("port")).map_err(|key| ("port", key))?;
    let end_port = values::port(&text("end_port")).map_err(|key| ("end_port", key))?;
    let to_port = values::port(&text("to_port")).map_err(|key| ("to_port", key))?;
    let given = port.is_some() || end_port.is_some() || to_port.is_some();
    if given && !has_ports(protocol.as_deref()) {
        return Err(("port", keys::WEB_NAT_ERROR_PORTS));
    }
    if port.is_none() && (end_port.is_some() || to_port.is_some()) {
        return Err(("port", keys::WEB_NAT_ERROR_NEEDS_PORT));
    }
    if end_port.is_some_and(|last| port.is_some_and(|first| last <= first)) {
        return Err(("end_port", keys::WEB_NAT_ERROR_RANGE));
    }
    if end_port.is_some() && to_port.is_some() {
        return Err(("to_port", keys::WEB_NAT_ERROR_TARGET_PORT));
    }
    let target = text("target");
    if target.parse::<Ipv4Addr>().is_err() && Mac::from_str(&target).is_err() {
        return Err(("target", keys::WEB_NAT_ERROR_TARGET));
    }
    Ok(Forward::new(
        (protocol, interface),
        (port, end_port),
        (target, to_port),
    ))
}

/// The Forward a port dialog on `router` with `values` and the router's interface `names`.
fn form(locale: Locale, router: &str, values: &Params, names: &[String]) -> FormDialog {
    let value = |name: &str| values.text(name).to_owned();
    let mut protocols = vec![Choice::word(locale, "", keys::WEB_NAT_ANY)];
    protocols.extend(
        PROTOCOLS
            .iter()
            .map(|(name, label)| Choice::word(locale, name, *label)),
    );
    let interfaces = names.iter().map(|name| Choice::plain(name)).collect();
    let port = |name: &'static str, label: MessageKey| {
        Input::new(name, label, value(name))
            .number(1, i64::from(u16::MAX))
            .optional()
            .rule(keys::WEB_ROUTING_ERROR_PORT)
    };
    let title = tr(locale, keys::WEB_NAT_ADD, None);
    FormDialog::network(locale, title, format!("/ui/r/{router}/nat/forward/new"))
        .submit(keys::WEB_NAT_ADD)
        .with_input(
            Input::new("protocol", keys::WEB_NAT_FIELD_PROTOCOL, value("protocol"))
                .optional()
                .select(protocols),
        )
        .with_input(
            Input::new("interface", keys::WEB_NAT_COL_INTERFACE, value("interface"))
                .select(interfaces),
        )
        .with_input(port("port", keys::WEB_NAT_FIELD_PORT).help(keys::WEB_NAT_HELP_PORT))
        .with_input(
            port("end_port", keys::WEB_NAT_FIELD_END_PORT).help(keys::WEB_NAT_HELP_END_PORT),
        )
        .with_input(
            Input::new("target", keys::WEB_NAT_FIELD_TARGET, value("target"))
                .max_chars(17)
                .help(keys::WEB_NAT_HELP_TARGET)
                .rule(keys::WEB_NAT_ERROR_TARGET),
        )
        .with_input(
            port("to_port", keys::WEB_NAT_FIELD_TARGET_PORT).help(keys::WEB_NAT_HELP_TARGET_PORT),
        )
}
