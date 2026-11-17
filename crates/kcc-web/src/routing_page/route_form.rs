//! The Add route dialog: its inputs for each address family and the checks of what was
//! typed, at the boundary.

use core::net::{Ipv4Addr, Ipv6Addr};

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::route_rows::{Family, StaticRoute, prefix};
use crate::page_kit::{
    form::{Choice, FormDialog, Input},
    request::Params,
    values,
};

/// The field naming the destination of `family`.
pub(crate) const fn destination_field(family: Family) -> &'static str {
    match family {
        Family::V4 => "network",
        Family::V6 => "prefix",
    }
}

/// The route the dialog describes, its addresses in the canonical form the router stores:
/// the network or prefix without host bits, every address as `Ipv4Addr` or `Ipv6Addr`
/// prints it.
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
    let (destination, mask_text) = destination(family, &text)?;
    let gateway = optional("gateway")
        .map(|address| match family {
            Family::V4 => address.parse::<Ipv4Addr>().map(|parsed| parsed.to_string()),
            Family::V6 => address.parse::<Ipv6Addr>().map(|parsed| parsed.to_string()),
        })
        .transpose()
        .map_err(|_error| {
            let message = match family {
                Family::V4 => keys::WEB_ROUTING_ERROR_IPV4,
                Family::V6 => keys::WEB_ROUTING_ERROR_IPV6,
            };
            ("gateway", message)
        })?;
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

/// The destination typed for `family` (read by `text`), without host bits: the IPv4
/// network and its mask, or the IPv6 prefix.
///
/// # Errors
///
/// Returns the field to correct and why.
fn destination(
    family: Family,
    text: &dyn Fn(&str) -> String,
) -> Result<(String, Option<String>), (&'static str, MessageKey)> {
    match family {
        Family::V4 => {
            let network = text("network")
                .parse::<Ipv4Addr>()
                .map_err(|_error| ("network", keys::WEB_ROUTING_ERROR_IPV4))?;
            let mask =
                values::netmask(&text("mask")).ok_or(("mask", keys::WEB_ROUTING_ERROR_MASK))?;
            let masked = Ipv4Addr::from(u32::from(network) & u32::from(mask));
            Ok((masked.to_string(), Some(mask.to_string())))
        }
        Family::V6 => {
            let (address, length) =
                prefix(&text("prefix")).ok_or(("prefix", keys::WEB_ROUTING_ERROR_PREFIX))?;
            let host_bits = u32::from(128_u8.saturating_sub(length));
            let network_bits = u128::MAX.checked_shl(host_bits).unwrap_or(0);
            let masked = Ipv6Addr::from(u128::from(address) & network_bits);
            Ok((format!("{masked}/{length}"), None))
        }
    }
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
    let mut choices = vec![Choice::word(locale, "", keys::WEB_ROUTING_NO_INTERFACE)];
    choices.extend(names.iter().map(|name| Choice::plain(name)));
    let post_to = format!("/ui/r/{router}/routing/route/new?family={}", family.slug());
    let mut dialog =
        FormDialog::network(locale, tr(locale, title, None), post_to).submit(keys::WEB_ROUTING_ADD);
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
