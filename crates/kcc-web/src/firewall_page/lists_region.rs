//! The access lists region of the firewall page: each list with where it applies and its
//! rules in the router's order, then the IPv6 lists or the note about them.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{
    rules_table::rules_view,
    snapshot::{Binding, List},
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::request::with_query,
    table::view::TableView,
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
    /// The IPv4 lists, each with its rules table.
    lists: Vec<(List, TableView)>,
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
        let locale = shell.locale();
        let tables = lists
            .into_iter()
            .enumerate()
            .map(|(index, list)| {
                let table = rules_view(&router, (&list, index.saturating_add(1)), (rules, locale));
                (list, table)
            })
            .collect();
        Self {
            shell,
            oob: false,
            router,
            lists: tables,
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
