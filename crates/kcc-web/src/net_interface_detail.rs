//! One interface's drawer.
//!
//! `GET /ui/r/{router}/network/detail?name=` answers the drawer: the interface's settings
//! with Edit where the role may change them, Enable or Disable, its counters and a traffic
//! chart, which listens to the interface's stream (`net_interface_traffic`).

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::interfaces::{self, Interface, InterfaceStatistics};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    dashboard, errors,
    net_change::scalar,
    net_interface_line::Line,
    net_interface_traffic::statistics,
    net_settings::Fact,
    page::{Localize as _, Shell},
    page_kit::{
        context,
        context::fragment_shell,
        family::Family,
        gate::Controls,
        request::{Params, missing, with_query},
        respond,
        respond::Answer,
    },
};

/// The drawer.
#[derive(Template)]
#[template(path = "partials/net_interface_detail.html")]
struct Drawer {
    /// Locale carrier.
    shell: Shell,
    /// "Interface Bridge0".
    title: String,
    /// Why the interface could not be read.
    problem: Option<String>,
    /// The settings, with Edit where the role may change them.
    facts: Vec<Fact>,
    /// Byte and packet counters.
    counters: Vec<Counter>,
    /// Enable or Disable, when the role may run it.
    toggle: Option<Toggle>,
    /// The traffic stream.
    stream: String,
    /// The chart's accessible name.
    chart_label: String,
    /// Chart axis unit patterns.
    units: String,
}

localized!(Drawer);

/// One counter of the drawer.
struct Counter {
    /// The localized label.
    label: String,
    /// The formatted value.
    value: String,
}

/// Enable or Disable.
struct Toggle {
    /// Where the button posts.
    href: String,
    /// The localized label.
    label: String,
    /// Whether it disables, which may cut kcc off.
    disables: bool,
}

/// The interface a drawer shows, to whom.
struct About<'call> {
    /// Router profile id.
    router: &'call str,
    /// Interface name.
    name: &'call ObjectName,
    /// The reader's locale.
    locale: Locale,
}

impl About<'_> {
    /// `key` in the reader's language.
    fn text(&self, key: MessageKey) -> String {
        tr(self.locale, key, None)
    }

    /// The drawer with no facts yet.
    fn drawer(&self) -> Drawer {
        let mut args = FluentArgs::new();
        args.set("name", self.name.as_str().to_owned());
        Drawer {
            shell: fragment_shell(self.locale),
            title: tr(self.locale, keys::WEB_NETWORK_DETAIL_TITLE, Some(&args)),
            problem: None,
            facts: Vec::new(),
            counters: Vec::new(),
            toggle: None,
            stream: with_query(
                &format!("/ui/sse/r/{}/network/traffic", self.router),
                &[("name", self.name.as_str())],
            ),
            chart_label: tr(self.locale, keys::WEB_NETWORK_TRAFFIC_CHART, Some(&args)),
            units: dashboard::units(self.locale),
        }
    }

    /// The address of the page action `action`, naming the interface.
    fn action_url(&self, action: &str) -> String {
        with_query(
            &format!("/ui/r/{}/network/{action}", self.router),
            &[("name", self.name.as_str())],
        )
    }

    /// The settings of `interface` as `line` reads them, with Edit where `controls` allow.
    fn facts(&self, line: &Line, interface: &Interface, controls: &Controls) -> Vec<Fact> {
        let edit = |operation: &str, action: &str| {
            controls.allows(operation).then(|| self.action_url(action))
        };
        let fact = |id, key, value| Fact::new(id, self.text(key), value);
        vec![
            fact(
                "iface-description",
                keys::WEB_SYSTEM_DESCRIPTION,
                line.description().map(str::to_owned),
            )
            .editable(edit("description", "description")),
            fact(
                "iface-security",
                keys::WEB_NETWORK_SECURITY,
                line.level_text(self.locale),
            )
            .editable(edit("security_level", "security-level").filter(|_| line.routed())),
            fact(
                "iface-type",
                keys::WEB_NETWORK_TYPE,
                line.kind().map(str::to_owned),
            ),
            fact(
                "iface-link",
                keys::WEB_NETWORK_LINK,
                line.link_text(self.locale),
            ),
            fact(
                "iface-state",
                keys::WEB_NETWORK_STATE,
                line.state_text(self.locale),
            ),
            fact(
                "iface-address",
                keys::WEB_NETWORK_ADDRESS,
                line.address().map(str::to_owned),
            ),
            fact(
                "iface-mac",
                keys::WEB_NETWORK_MAC,
                scalar(interface.extra.get("mac")),
            ),
            fact(
                "iface-mtu",
                keys::WEB_NETWORK_MTU,
                scalar(interface.extra.get("mtu")),
            ),
            fact(
                "iface-gateway",
                keys::WEB_NETWORK_DEFAULT_GATEWAY,
                interface.defaultgw.map(|used| {
                    self.text(if used {
                        keys::COMMON_YES
                    } else {
                        keys::COMMON_NO
                    })
                }),
            ),
            fact(
                "iface-priority",
                keys::WEB_NETWORK_PRIORITY,
                interface.priority.map(|priority| priority.to_string()),
            ),
        ]
    }

    /// Enable or Disable for `line`, when `controls` allow it.
    fn toggle(&self, line: &Line, controls: &Controls) -> Option<Toggle> {
        let disables = line.enabled() != Some(false);
        let (operation, label) = if disables {
            ("down", keys::WEB_NETWORK_DISABLE)
        } else {
            ("up", keys::WEB_NETWORK_ENABLE)
        };
        controls.allows(operation).then(|| Toggle {
            href: with_query(
                &format!("/ui/r/{}/network/state", self.router),
                &[("name", self.name.as_str()), ("state", operation)],
            ),
            label: self.text(label),
            disables,
        })
    }

    /// The byte and packet counters of `stats`.
    fn counters(&self, stats: &InterfaceStatistics) -> Vec<Counter> {
        [
            (keys::WEB_NETWORK_RECEIVED, stats.rxbytes, true),
            (keys::WEB_NETWORK_SENT, stats.txbytes, true),
            (keys::WEB_NETWORK_PACKETS_RECEIVED, stats.rxpackets, false),
            (keys::WEB_NETWORK_PACKETS_SENT, stats.txpackets, false),
        ]
        .into_iter()
        .filter_map(|(key, count, bytes)| {
            count.map(|value| Counter {
                label: self.text(key),
                value: if bytes {
                    format::bytes(self.locale, value)
                } else {
                    format::integer(self.locale, value)
                },
            })
        })
        .collect()
    }
}

/// `GET /ui/r/{router}/network/detail?name=`: the drawer of one interface.
///
/// # Errors
///
/// Answers 404 for a missing or unknown interface, and the bare status when the router is
/// not visible.
// cancel-safe: reads only.
pub(crate) async fn drawer(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let target = context::target(&state, &user, &router)
        .await
        .map_err(|refusal| Answer::from(refusal.status()))?;
    let about = About {
        router: &router,
        name: &name,
        locale: user.locale(),
    };
    let mut drawer = about.drawer();
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let mut found = match interfaces::read_interfaces(&domain).await {
                Ok(found) => found,
                Err(error) => {
                    tracing::warn!(%error, "interface drawer: router read failed");
                    drawer.problem = Some(about.text(Family::Changes.unreachable()));
                    return Ok(respond::in_dialog(errors::render(&drawer)));
                }
            };
            let interface = found.remove(name.as_str()).ok_or_else(missing)?;
            let line = Line::new(name.as_str().to_owned(), &interface);
            let controls = Controls::new(user.role(), &router)
                .with_operations(interfaces::DESCRIPTOR.write_ops, Some(facts.catalog()));
            drawer.facts = about.facts(&line, &interface, &controls);
            drawer.toggle = about.toggle(&line, &controls);
            if let Some(stats) = statistics(&domain, &name).await {
                drawer.counters = about.counters(&stats);
            }
        }
        Err(error) => drawer.problem = Some(about.text(error.message(Family::Changes))),
    }
    Ok(respond::in_dialog(errors::render(&drawer)))
}
