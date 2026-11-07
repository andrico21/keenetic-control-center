//! The Add route dialog: its inputs for each address family and the checks of what was
//! typed, at the boundary.

use core::net::{Ipv4Addr, Ipv6Addr};

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::route_rows::{Family, StaticRoute, mask, prefix};
use crate::{
    net_change::Params,
    net_form::{Choice, FormDialog, Input},
};

/// The field naming the destination of `family`.
pub(crate) const fn destination_field(family: Family) -> &'static str {
    match family {
        Family::V4 => "network",
        Family::V6 => "prefix",
    }
}

/// The route the dialog describes.
///
/// # Errors
///
/// Returns the field to correct and why.
pub(crate) fn check(
    family: Family,
    values: &Params,
    names: &[String],
) -> Result<StaticRoute, (&'static str, MessageKey)> {
    let text = |name: &str| values.text(name).trim().to_owned();
    let optional = |name: &str| Some(text(name)).filter(|value| !value.is_empty());
    let (destination, mask_text) = match family {
        Family::V4 => {
            let network = text("network");
            if network.parse::<Ipv4Addr>().is_err() {
                return Err(("network", keys::WEB_ROUTING_ERROR_IPV4));
            }
            let given = text("mask");
            if !mask(&given) {
                return Err(("mask", keys::WEB_ROUTING_ERROR_MASK));
            }
            (network, Some(given))
        }
        Family::V6 => {
            let given = text("prefix");
            if !prefix(&given) {
                return Err(("prefix", keys::WEB_ROUTING_ERROR_PREFIX));
            }
            (given, None)
        }
    };
    let gateway = optional("gateway");
    let valid_gateway = gateway.as_deref().is_none_or(|address| match family {
        Family::V4 => address.parse::<Ipv4Addr>().is_ok(),
        Family::V6 => address.parse::<Ipv6Addr>().is_ok(),
    });
    if !valid_gateway {
        let message = match family {
            Family::V4 => keys::WEB_ROUTING_ERROR_IPV4,
            Family::V6 => keys::WEB_ROUTING_ERROR_IPV6,
        };
        return Err(("gateway", message));
    }
    let interface = optional("interface");
    if interface.as_ref().is_some_and(|name| !names.contains(name)) {
        return Err(("interface", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    if gateway.is_none() && interface.is_none() {
        return Err(("gateway", keys::WEB_ROUTING_ERROR_VIA));
    }
    let metric = match (family, optional("metric")) {
        (Family::V4, Some(number)) => Some(
            number
                .parse::<u16>()
                .map(u32::from)
                .map_err(|_error| ("metric", keys::WEB_ROUTING_ERROR_NUMBER))?,
        ),
        (Family::V4 | Family::V6, _) => None,
    };
    Ok(StaticRoute::new(
        family,
        (destination, mask_text),
        (gateway, interface),
        metric,
    ))
}

/// The Add route dialog of `family` on `router` with `values` and the router's interface
/// `names`.
pub(crate) fn form(
    locale: Locale,
    (router, family): (&str, Family),
    values: &Params,
    names: &[String],
) -> FormDialog {
    let (title, help) = match family {
        Family::V4 => (keys::WEB_ROUTING_ADD_TITLE, keys::WEB_ROUTING_ERROR_IPV4),
        Family::V6 => (keys::WEB_ROUTING_ADD_TITLE_V6, keys::WEB_ROUTING_ERROR_IPV6),
    };
    let value = |name: &str| values.text(name).to_owned();
    let mut choices = vec![Choice::keyed("", keys::WEB_ROUTING_NO_INTERFACE, locale)];
    choices.extend(names.iter().map(|name| Choice::plain(name)));
    let post_to = format!("/ui/r/{router}/routing/route/new?family={}", family.slug());
    let mut dialog = FormDialog::new(locale, tr(locale, title, None), post_to)
        .with_submit(keys::WEB_ROUTING_ADD);
    dialog = match family {
        Family::V4 => dialog
            .with_input(
                Input::new("network", keys::WEB_ROUTING_FIELD_NETWORK, value("network"))
                    .max_chars(15)
                    .help(keys::WEB_ROUTING_HELP_NETWORK)
                    .rule(keys::WEB_ROUTING_ERROR_IPV4),
            )
            .with_input(
                Input::new("mask", keys::WEB_ROUTING_FIELD_MASK, value("mask"))
                    .max_chars(15)
                    .help(keys::WEB_ROUTING_HELP_MASK)
                    .rule(keys::WEB_ROUTING_ERROR_MASK),
            ),
        Family::V6 => dialog.with_input(
            Input::new("prefix", keys::WEB_ROUTING_FIELD_PREFIX, value("prefix"))
                .max_chars(43)
                .help(keys::WEB_ROUTING_HELP_PREFIX)
                .rule(keys::WEB_ROUTING_ERROR_PREFIX),
        ),
    };
    dialog = dialog
        .with_input(
            Input::new("gateway", keys::WEB_ROUTING_FIELD_GATEWAY, value("gateway"))
                .max_chars(39)
                .optional()
                .help(keys::WEB_ROUTING_HELP_GATEWAY)
                .rule(help),
        )
        .with_input(
            Input::new(
                "interface",
                keys::WEB_ROUTING_FIELD_INTERFACE,
                value("interface"),
            )
            .optional()
            .select(choices),
        );
    if family == Family::V4 {
        dialog = dialog.with_input(
            Input::new("metric", keys::WEB_ROUTING_FIELD_METRIC, value("metric"))
                .number(0, i64::from(u16::MAX))
                .optional()
                .help(keys::WEB_ROUTING_HELP_METRIC)
                .rule(keys::WEB_ROUTING_ERROR_NUMBER),
        );
    }
    dialog
}
