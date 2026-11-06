//! What the DNS tabs show, read through the DNS domain: the servers the router asks, the
//! filtering settings, the static records, the domain lists and the routes by domain list.
//!
//! The domain keeps the running configuration as untyped trees. The members read here
//! follow the catalog's argument names (`address`, `domain`, `name`, `group`, ...) and a
//! missing member leaves its value unreported; real-router shapes are not verified yet.

use kcc_domain::{
    Result as DomainResult, RouterCtx,
    dns::{self, DnsConfiguration, DnsProxyState, UpstreamCollection},
};
use serde_json::Value;

/// How the router reaches a DNS server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// DNS over TLS.
    Tls,
    /// DNS over HTTPS.
    Https,
    /// Plain DNS.
    Plain,
}

/// One entry of a configured list: its name and the texts the row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The entry's name: a server, a domain, a list, a target.
    name: String,
    /// Further values, in column order; `None` where the router reported nothing.
    values: Vec<Option<String>>,
    /// Addresses or domains the entry holds.
    lists: Vec<Vec<String>>,
}

impl Entry {
    /// The entry's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Value `index`, in column order.
    pub(crate) fn value(&self, index: usize) -> Option<&str> {
        self.values.get(index).and_then(Option::as_deref)
    }

    /// List `index`.
    pub(crate) fn list(&self, index: usize) -> Vec<String> {
        self.lists.get(index).cloned().unwrap_or_default()
    }
}

/// The DNS state of one router: `show dns-proxy` and the running DNS configuration.
#[derive(Debug, Clone)]
pub(crate) struct DnsState {
    /// The DNS proxy as shown.
    proxy: DnsProxyState,
    /// The running configuration.
    config: DnsConfiguration,
}

impl DnsState {
    /// Reads the DNS state of the router of `ctx`.
    ///
    /// # Errors
    ///
    /// Returns the domain's error when either read fails.
    // cancel-safe: reads only.
    pub(crate) async fn read(ctx: &RouterCtx) -> DomainResult<Self> {
        let proxy = dns::read_dns_proxy(ctx).await?;
        let read = dns::read_configuration(ctx).await?;
        // `read_configuration` deserializes the root answer, so its `show.rc` wrapper ends
        // up as an unknown member; the configuration is inside it.
        let config = read
            .extra
            .get("show")
            .and_then(|show| show.get("rc"))
            .cloned()
            .and_then(|tree| serde_json::from_value(tree).ok())
            .unwrap_or(read);
        Ok(Self { proxy, config })
    }

    /// The servers the router asks, with their protocol and further arguments.
    pub(crate) fn servers(&self) -> Vec<(Protocol, Entry)> {
        let mut servers = upstreams(Protocol::Tls, self.proxy.tls.as_ref());
        servers.extend(upstreams(Protocol::Https, self.proxy.https.as_ref()));
        let plain = items(self.config.ip.as_ref().and_then(|ip| ip.get("name-server")));
        servers.extend(plain.into_iter().filter_map(|item| {
            let address = text(item, &["address"]).or_else(|| scalar(item))?;
            Some((Protocol::Plain, entry(address, vec![None], Vec::new())))
        }));
        servers
    }

    /// Static records: the domain and its address.
    pub(crate) fn records(&self) -> Vec<Entry> {
        items(self.config.ip.as_ref().and_then(|ip| ip.get("host")))
            .into_iter()
            .filter_map(|item| {
                let domain = text(item, &["domain", "name"])?;
                Some(entry(domain, vec![text(item, &["address"])], Vec::new()))
            })
            .collect()
    }

    /// Domain lists: the name, the description, the included and excluded domains.
    pub(crate) fn lists(&self) -> Vec<Entry> {
        let groups = self.config.object_group.as_ref();
        items(groups.and_then(|group| group.get("fqdn")))
            .into_iter()
            .filter_map(|item| {
                let name = text(item, &["name"])?;
                let lists = ["include", "exclude"]
                    .iter()
                    .map(|member| texts(item.get(*member)))
                    .collect();
                Some(entry(name, vec![text(item, &["description"])], lists))
            })
            .collect()
    }

    /// Routes by domain list: the list, the interface, the gateway.
    pub(crate) fn routes(&self) -> Vec<Entry> {
        let route = self.proxy_tree("route");
        let entries = route
            .and_then(|tree| tree.get("object-group"))
            .map_or_else(|| items(route), |groups| items(Some(groups)));
        entries
            .into_iter()
            .filter_map(|item| {
                let group = text(item, &["group", "object-group", "name"])?;
                let values = vec![text(item, &["interface"]), text(item, &["gateway"])];
                Some(entry(group, values, Vec::new()))
            })
            .collect()
    }

    /// The filtering engine, when one is set.
    pub(crate) fn engine(&self) -> Option<String> {
        self.proxy_tree("filter")
            .and_then(|filter| text(filter, &["engine"]))
            .or_else(|| {
                let shown = self.proxy.filter.as_ref()?;
                text(shown, &["engine"]).or_else(|| scalar(shown))
            })
    }

    /// Whether DNS interception is on; `None` when the router reports nothing.
    pub(crate) fn intercept(&self) -> Option<bool> {
        let configured = self
            .proxy_tree("intercept")
            .map(|tree| match tree.get("enable") {
                Some(Value::Bool(enabled)) => *enabled,
                Some(_) | None => tree
                    .as_object()
                    .is_some_and(|object| object.contains_key("enable")),
            });
        configured.or_else(|| self.proxy.intercept.as_ref().and_then(Value::as_bool))
    }

    /// Filter profiles: the name and the description.
    pub(crate) fn profiles(&self) -> Vec<Entry> {
        let filter = self.proxy_tree("filter");
        items(filter.and_then(|tree| tree.get("profile")))
            .into_iter()
            .filter_map(|item| {
                let name = text(item, &["name"])?;
                Some(entry(name, vec![text(item, &["description"])], Vec::new()))
            })
            .collect()
    }

    /// Profile assignments: the host or interface, its kind and the profile or preset.
    pub(crate) fn assignments(&self) -> Vec<(bool, Entry)> {
        let assign = self
            .proxy_tree("filter")
            .and_then(|filter| filter.get("assign"));
        let mut found = Vec::new();
        for (host, member) in [(true, "host"), (false, "interface")] {
            for item in items(assign.and_then(|tree| tree.get(member))) {
                if let Some(target) = text(item, &[member]) {
                    let applied = text(item, &["profile", "preset"]);
                    found.push((host, entry(target, vec![applied], Vec::new())));
                }
            }
        }
        found
    }

    /// The member `name` of the configured `dns-proxy` tree.
    fn proxy_tree(&self, name: &str) -> Option<&Value> {
        self.config.dns_proxy.as_ref()?.get(name)
    }
}

/// An entry named `name` with `values` and `lists`.
const fn entry(name: String, values: Vec<Option<String>>, lists: Vec<Vec<String>>) -> Entry {
    Entry {
        name,
        values,
        lists,
    }
}

/// The upstreams of one protocol: the server, then its further arguments.
fn upstreams(
    protocol: Protocol,
    collection: Option<&UpstreamCollection>,
) -> Vec<(Protocol, Entry)> {
    collection
        .into_iter()
        .flat_map(|upstreams| upstreams.upstream.iter())
        .filter_map(|row| {
            let (server, rest) = row.split_first()?;
            let options = (!rest.is_empty()).then(|| rest.join(" "));
            Some((protocol, entry(server.clone(), vec![options], Vec::new())))
        })
        .collect()
}

/// The items of `value`: an array's members, or an object as the only item.
fn items(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(members)) => members.iter().collect(),
        Some(object @ Value::Object(_)) => vec![object],
        Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) | None => {
            Vec::new()
        }
    }
}

/// The first of the members `names` of `item` that is a string or a number.
fn text(item: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| item.get(*name).and_then(scalar))
}

/// `value` as text, when it is a string or a number.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(string) => Some(string.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Every text of a list member: strings, or objects' `address` members.
fn texts(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(members)) => members
            .iter()
            .filter_map(|member| scalar(member).or_else(|| text(member, &["address"])))
            .collect(),
        Some(single @ (Value::Object(_) | Value::String(_))) => scalar(single)
            .or_else(|| text(single, &["address"]))
            .into_iter()
            .collect(),
        Some(Value::Null | Value::Bool(_) | Value::Number(_)) | None => Vec::new(),
    }
}

#[cfg(test)]
#[path = "dns_read_tests.rs"]
mod tests;
