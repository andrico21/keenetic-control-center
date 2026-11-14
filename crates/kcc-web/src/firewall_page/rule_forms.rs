//! The Add rule dialog of the firewall page.
//!
//! It takes a list (an existing one or a new name), the decision, the protocol and both
//! sides: address, mask and, for TCP and UDP, an exact port.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::firewall::descriptor::DESCRIPTOR;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    checks::{address, list_name, port},
    expect::Expect,
    lines,
    rule::{PROTOCOLS, Parsed, Side},
    rule_actions::filtered,
    run::{Planned, Sender},
    snapshot,
    views::Spot,
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_form::{Choice, FormDialog, Input},
    page_kit::{action::Operation, request::Params, respond::Answer, submit::Invalid},
    routing_page::{reply::unread, route_rows::mask},
    system_pages::shared::merged,
};

/// A rule added, audited as `web.firewall_rule_add`.
const ADD: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_add");

/// `GET /ui/r/{router}/firewall/rule/new[?list=]`: the Add rule dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn add_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = ADD.open(&state, &user, &router).await?;
    let pairs = merged(query.as_deref(), Vec::new());
    let values = Params::new(pairs, Vec::new());
    Ok(add_form(action.locale(), &router, &values).show())
}

/// `POST /ui/r/{router}/firewall/rule/new`: checks the rule, adds it and reads it back.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), 403 for a management change the role
/// may not make, and what the kit answers when the router or the permission is missing.
pub(crate) async fn add(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = ADD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let values = Params::of(pairs.clone());
    let path = format!("/ui/r/{router}/firewall/rule/new");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &values, add_form(locale, &router, &values))
        .submit_reading(
            async |submitted, domain| {
                let (list, rule) =
                    check(submitted).map_err(|(field, rule)| Invalid::at(field, rule))?;
                let firewall = snapshot::read(domain)
                    .await
                    .map_err(|message| unread(locale, message))?;
                let words = rule.words();
                let count = firewall.list(&list).map_or(0, |found| {
                    found
                        .entries()
                        .iter()
                        .filter(|entry| entry.rule().words() == words.as_slice())
                        .count()
                });
                if count > 0 {
                    return Err(Invalid::at("source", keys::WEB_ROUTING_ERROR_DUPLICATE).into());
                }
                Ok(lines::add_rule(domain, &list, &rule).map(|request| {
                    let interfaces = filtered(&firewall, &list);
                    let expect = Expect::Count {
                        list,
                        words,
                        count: 1,
                    };
                    Planned::new(request, expect, interfaces)
                }))
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}

/// The list and rule the Add rule dialog describes.
///
/// # Errors
///
/// Returns the field to correct and why.
fn check(values: &Params) -> Result<(String, Parsed), (&'static str, MessageKey)> {
    let text = |name: &str| values.text(name).trim().to_owned();
    let list = text("list");
    if !list_name(&list) {
        return Err(("list", keys::WEB_ROUTING_ERROR_NAME));
    }
    let action = text("action");
    if action != "permit" && action != "deny" {
        return Err(("action", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let protocol = text("protocol");
    if !PROTOCOLS.iter().any(|(name, _)| *name == protocol) {
        return Err(("protocol", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let side = |fields: [&'static str; 3]| {
        let [host, netmask, number] = fields;
        if !address(&text(host)) {
            return Err((host, keys::WEB_ROUTING_ERROR_IPV4));
        }
        if !mask(&text(netmask)) {
            return Err((netmask, keys::WEB_ROUTING_ERROR_MASK));
        }
        let found = port(&text(number)).map_err(|key| (number, key))?;
        if found.is_some() && !matches!(protocol.as_str(), "tcp" | "udp") {
            return Err((number, keys::WEB_NAT_ERROR_PORTS));
        }
        Ok(Side::new(text(host), text(netmask), found))
    };
    let source = side(["source", "source_mask", "source_port"])?;
    let destination = side(["destination", "destination_mask", "destination_port"])?;
    Ok((
        list,
        Parsed::new((action, Some(protocol)), source, destination),
    ))
}

/// The Add rule dialog on `router` with `values`.
fn add_form(locale: Locale, router: &str, values: &Params) -> FormDialog {
    let value = |name: &str| values.text(name).to_owned();
    let actions = vec![
        Choice::keyed("permit", keys::WEB_FIREWALL_ACTION_PERMIT, locale),
        Choice::keyed("deny", keys::WEB_FIREWALL_ACTION_DENY, locale),
    ];
    let protocols = PROTOCOLS
        .iter()
        .map(|(name, label)| Choice::keyed(name, *label, locale))
        .collect();
    let address_input = |name: &'static str, label: MessageKey| {
        Input::new(name, label, value(name))
            .max_chars(15)
            .rule(keys::WEB_ROUTING_ERROR_IPV4)
    };
    let mask_input = |name: &'static str, label: MessageKey| {
        Input::new(name, label, value(name))
            .max_chars(15)
            .help(keys::WEB_FIREWALL_HELP_ADDRESS)
            .rule(keys::WEB_ROUTING_ERROR_MASK)
    };
    let port_input = |name: &'static str, label: MessageKey| {
        Input::new(name, label, value(name))
            .number(1, i64::from(u16::MAX))
            .optional()
            .help(keys::WEB_FIREWALL_HELP_PORT)
            .rule(keys::WEB_ROUTING_ERROR_PORT)
    };
    let title = tr(locale, keys::WEB_FIREWALL_ADD, None);
    FormDialog::new(locale, title, format!("/ui/r/{router}/firewall/rule/new"))
        .with_submit(keys::WEB_FIREWALL_ADD)
        .with_input(
            Input::new("list", keys::WEB_FIREWALL_FIELD_LIST, value("list"))
                .max_chars(64)
                .help(keys::WEB_FIREWALL_HELP_LIST)
                .rule(keys::WEB_ROUTING_ERROR_NAME),
        )
        .with_input(
            Input::new("action", keys::WEB_FIREWALL_FIELD_ACTION, value("action")).select(actions),
        )
        .with_input(
            Input::new("protocol", keys::WEB_NAT_FIELD_PROTOCOL, value("protocol"))
                .select(protocols),
        )
        .with_input(address_input("source", keys::WEB_FIREWALL_FIELD_SOURCE))
        .with_input(mask_input(
            "source_mask",
            keys::WEB_FIREWALL_FIELD_SOURCE_MASK,
        ))
        .with_input(port_input(
            "source_port",
            keys::WEB_FIREWALL_FIELD_SOURCE_PORT,
        ))
        .with_input(address_input(
            "destination",
            keys::WEB_FIREWALL_FIELD_DESTINATION,
        ))
        .with_input(mask_input(
            "destination_mask",
            keys::WEB_FIREWALL_FIELD_DESTINATION_MASK,
        ))
        .with_input(port_input(
            "destination_port",
            keys::WEB_FIREWALL_FIELD_DESTINATION_PORT,
        ))
}
