//! The access lists region of the firewall page: each list with where it applies and its
//! rules in the router's order, then the IPv6 lists or the note about them.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{
    rule::{Parsed, Side},
    snapshot::{Binding, Entry, List},
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::request::with_query,
};

/// The access lists and their rules (`partials/firewall_lists.html`).
#[derive(Template)]
#[template(path = "partials/firewall_lists.html")]
pub(crate) struct ListsRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// Router profile id.
    router: String,
    /// The IPv4 lists.
    lists: Vec<List>,
    /// Every list applied to an interface.
    bindings: Vec<Binding>,
    /// Whether the role may change rules.
    rules: bool,
    /// Whether the role may apply lists.
    bind: bool,
    /// The IPv6 lists, when the router's catalog has them.
    ipv6: Option<Vec<List>>,
}

localized!(ListsRegion);

impl ListsRegion {
    /// The region of `lists` and `bindings` on `router` in `shell`; `ipv6` when the
    /// router's catalog has IPv6 lists; `(rules, bind)` as the role may change them.
    pub(crate) fn new(
        (shell, router): (Shell, String),
        (lists, bindings, ipv6): (Vec<List>, Vec<Binding>, Option<Vec<List>>),
        (rules, bind): (bool, bool),
    ) -> Self {
        Self {
            shell,
            oob: false,
            router,
            lists,
            bindings,
            rules,
            bind,
            ipv6,
        }
    }

    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// Where `list` is applied, as people read it.
    fn applied(&self, list: &List) -> Vec<String> {
        self.bindings
            .iter()
            .filter(|binding| binding.list() == list.name())
            .map(|binding| self.binding_text(binding))
            .collect()
    }

    /// `interface, direction` of `binding`.
    fn binding_text(&self, binding: &Binding) -> String {
        let mut args = FluentArgs::new();
        args.set("name", binding.interface().to_owned());
        args.set(
            "value",
            tr(
                self.shell.locale(),
                direction_label(binding.direction()),
                None,
            ),
        );
        tr(self.shell.locale(), keys::WEB_FIREWALL_BINDING, Some(&args))
    }

    /// The decision of `entry`, or the first stored word of a rule in another form.
    fn action(&self, entry: &Entry) -> String {
        entry.rule().parsed().map_or_else(
            || entry.rule().text(),
            |rule| tr(self.shell.locale(), rule.action_label(), None),
        )
    }

    /// The protocol of `entry`.
    fn protocol(&self, entry: &Entry) -> String {
        entry
            .rule()
            .parsed()
            .and_then(Parsed::protocol_label)
            .map_or_else(String::new, |label| tr(self.shell.locale(), label, None))
    }

    /// The source of `entry`.
    fn source(&self, entry: &Entry) -> String {
        entry
            .rule()
            .parsed()
            .map_or_else(String::new, |rule| self.side(rule.source()))
    }

    /// The destination of `entry`.
    fn destination(&self, entry: &Entry) -> String {
        entry
            .rule()
            .parsed()
            .map_or_else(String::new, |rule| self.side(rule.destination()))
    }

    /// One side as people read it: the address (or Any) and the port.
    fn side(&self, side: &Side) -> String {
        let locale = self.shell.locale();
        let address = side
            .address_text()
            .unwrap_or_else(|| tr(locale, keys::WEB_FIREWALL_ANY_ADDRESS, None));
        match side.port() {
            None => address,
            Some(port) => {
                let mut args = FluentArgs::new();
                args.set("port", port.to_string());
                format!(
                    "{address} {}",
                    tr(locale, keys::WEB_FIREWALL_PORT, Some(&args))
                )
            }
        }
    }

    /// The address of the rule action `action` on `entry` of `list`.
    fn rule_url(&self, action: &str, list: &List, entry: &Entry) -> String {
        let index = entry.index().to_string();
        let words = entry.rule().text();
        with_query(
            &format!("/ui/r/{}/firewall/rule/{action}", self.router),
            &[("list", list.name()), ("index", &index), ("rule", &words)],
        )
    }

    /// The address moving `entry` of `list` one up, unless it is first.
    fn up_url(&self, list: &List, entry: &Entry) -> Option<String> {
        let to = entry.index().checked_sub(1)?;
        Some(format!("{}&to={to}", self.rule_url("move", list, entry)))
    }

    /// The address moving `entry` of `list` one down, unless it is last.
    fn down_url(&self, list: &List, entry: &Entry) -> Option<String> {
        let to = entry.index().saturating_add(1);
        (to < list.entries().len())
            .then(|| format!("{}&to={to}", self.rule_url("move", list, entry)))
    }

    /// The address turning `entry` of `list` on or off.
    fn state_url(&self, list: &List, entry: &Entry) -> String {
        let value = if entry.disabled() { "on" } else { "off" };
        format!("{}&value={value}", self.rule_url("state", list, entry))
    }

    /// The address of the Add rule dialog for `list`.
    fn add_url(&self, list: &List) -> String {
        with_query(
            &format!("/ui/r/{}/firewall/rule/new", self.router),
            &[("list", list.name())],
        )
    }

    /// The address of the dialog applying `list` to an interface.
    fn bind_url(&self, list: &List) -> String {
        with_query(
            &format!("/ui/r/{}/firewall/bind", self.router),
            &[("list", list.name())],
        )
    }
}

/// The label of a binding direction.
pub(crate) fn direction_label(direction: &str) -> MessageKey {
    if direction == "out" {
        keys::WEB_FIREWALL_DIRECTION_OUT
    } else {
        keys::WEB_FIREWALL_DIRECTION_IN
    }
}
