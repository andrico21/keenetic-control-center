//! The dialog applying an access list to an interface, and the checks of its values.

use fluent_bundle::FluentArgs;
use kcc_domain::firewall::model::Direction;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    lists_region::direction_label,
    snapshot::{Binding, Snapshot},
};
use crate::{
    net_change::Params,
    net_form::{Choice, FormDialog, Input},
};

/// The direction a parameter names.
pub(crate) fn direction(text: &str) -> Option<Direction> {
    match text {
        "in" => Some(Direction::In),
        "out" => Some(Direction::Out),
        _ => None,
    }
}

/// The binding the dialog describes.
///
/// # Errors
///
/// Returns the field to correct and why.
pub(crate) fn check(
    values: &Params,
    (firewall, names): (&Snapshot, &[String]),
) -> Result<(Binding, Direction), (&'static str, MessageKey)> {
    let list = values.text("list").trim();
    if firewall.list(list).is_none() {
        return Err(("list", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let interface = values.text("interface").trim();
    if !names.iter().any(|name| name == interface) {
        return Err(("interface", keys::WEB_ROUTING_ERROR_CHOICE));
    }
    let side = values.text("direction").trim();
    let way = direction(side).ok_or(("direction", keys::WEB_ROUTING_ERROR_CHOICE))?;
    let binding = Binding::new(interface.to_owned(), list.to_owned(), side.to_owned());
    if firewall.bindings().contains(&binding) {
        return Err(("interface", keys::WEB_ROUTING_ERROR_DUPLICATE));
    }
    Ok((binding, way))
}

/// `interface, direction` of `binding` in `locale`.
pub(crate) fn where_text(locale: Locale, binding: &Binding) -> String {
    let mut args = FluentArgs::new();
    args.set("name", binding.interface().to_owned());
    args.set(
        "value",
        tr(locale, direction_label(binding.direction()), None),
    );
    tr(locale, keys::WEB_FIREWALL_BINDING, Some(&args))
}

/// The dialog applying a list on `router` with `values`, the router's lists and interface
/// `names`.
pub(crate) fn form(
    locale: Locale,
    router: &str,
    values: &Params,
    (firewall, names): (&Snapshot, &[String]),
) -> FormDialog {
    let value = |name: &str| values.text(name).to_owned();
    let lists = firewall
        .lists()
        .iter()
        .map(|list| Choice::plain(list.name()))
        .collect();
    let interfaces = names.iter().map(|name| Choice::plain(name)).collect();
    let ways = vec![
        Choice::keyed("in", keys::WEB_FIREWALL_DIRECTION_IN, locale),
        Choice::keyed("out", keys::WEB_FIREWALL_DIRECTION_OUT, locale),
    ];
    let title = tr(locale, keys::WEB_FIREWALL_BIND_TITLE, None);
    FormDialog::new(locale, title, format!("/ui/r/{router}/firewall/bind"))
        .with_submit(keys::WEB_FIREWALL_BIND)
        .with_input(Input::new("list", keys::WEB_FIREWALL_FIELD_LIST, value("list")).select(lists))
        .with_input(
            Input::new(
                "interface",
                keys::WEB_ROUTING_FIELD_INTERFACE,
                value("interface"),
            )
            .select(interfaces),
        )
        .with_input(
            Input::new(
                "direction",
                keys::WEB_FIREWALL_FIELD_DIRECTION,
                value("direction"),
            )
            .select(ways)
            .help(keys::WEB_FIREWALL_HELP_DIRECTION),
        )
}
