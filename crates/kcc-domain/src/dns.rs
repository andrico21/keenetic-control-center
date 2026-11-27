//! DNS proxy, resolver, static-record, and domain-list operations.

mod change;

use alloc::collections::BTreeMap;

use kcc_app::workflow::CliChangeRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ChangeOp, DomainDescriptor, DomainId, OperationDescriptor, Result, RouterCtx, decode,
    descriptor, read_show,
};

/// Tolerant encrypted-upstream collection.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct UpstreamCollection {
    /// Upstream argument rows as returned by the router.
    pub upstream: Vec<Vec<String>>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant `show dns-proxy` model.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub struct DnsProxyState {
    /// DNS-over-TLS upstreams.
    pub tls: Option<UpstreamCollection>,
    /// DNS-over-HTTPS upstreams.
    pub https: Option<UpstreamCollection>,
    /// Configured filtering engine.
    pub filter: Option<Value>,
    /// Whether DNS interception is enabled.
    pub intercept: Option<Value>,
    /// Rebinding protection state.
    #[serde(rename = "rebind-protect")]
    pub rebind_protect: Option<Value>,
    /// Maximum answer TTL.
    #[serde(rename = "max-ttl")]
    pub max_ttl: Option<u32>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Tolerant running DNS configuration tree.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub struct DnsConfiguration {
    /// DNS proxy configuration.
    #[serde(rename = "dns-proxy")]
    pub dns_proxy: Option<Value>,
    /// IP resolver and static-host configuration.
    pub ip: Option<Value>,
    /// FQDN object groups.
    #[serde(rename = "object-group")]
    pub object_group: Option<Value>,
    /// `NextDNS` configuration.
    pub nextdns: Option<Value>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Filtering engine selected by `dns-proxy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FilterEngine {
    /// Built-in interception engine.
    Interceptor,
    /// `NextDNS` engine.
    NextDns,
    /// Package-provided engine.
    Opkg,
    /// Public resolver engine.
    Public,
    /// `SkyDNS` engine.
    SkyDns,
}

/// DNS rebinding protection mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RebindProtection {
    /// Automatically select protection behavior.
    Auto,
    /// Enforce strict protection.
    Strict,
}

/// DNS-over-TLS upstream settings.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TlsUpstream {
    /// Resolver IP address.
    pub address: String,
    /// Optional resolver port.
    pub port: Option<u16>,
    /// Optional TLS server name.
    pub server_name: Option<String>,
    /// Optional SPKI hash.
    pub spki_hash: Option<String>,
    /// Optional source interface.
    pub interface: Option<String>,
    /// Optional DNS suffix routed to this resolver.
    pub domain: Option<String>,
}

impl TlsUpstream {
    /// Creates a DNS-over-TLS upstream at `address` with no optional settings.
    #[inline]
    #[must_use]
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            port: None,
            server_name: None,
            spki_hash: None,
            interface: None,
            domain: None,
        }
    }
}

/// DNS-over-HTTPS upstream settings.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HttpsUpstream {
    /// Resolver URL.
    pub url: String,
    /// Optional response format (`dnsm` or `json`).
    pub format: Option<String>,
    /// Optional SNI/SPKI hash.
    pub hash: Option<String>,
    /// Optional source interface.
    pub interface: Option<String>,
    /// Optional DNS suffix routed to this resolver.
    pub domain: Option<String>,
}

impl HttpsUpstream {
    /// Creates a DNS-over-HTTPS upstream with no optional routing constraints.
    #[inline]
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            format: None,
            hash: None,
            interface: None,
            domain: None,
        }
    }

    /// Sets the resolver response format.
    #[inline]
    #[must_use]
    pub fn with_format(mut self, format: &str) -> Self {
        self.format = Some(format.to_owned());
        self
    }

    /// Restricts the upstream to an interface.
    #[inline]
    #[must_use]
    pub fn on_interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.to_owned());
        self
    }
}

/// DNS-based route settings.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub struct DnsRoute {
    /// FQDN object-group name.
    pub group: String,
    /// Gateway keyword when configured.
    pub gateway: Option<String>,
    /// Egress interface.
    pub interface: Option<String>,
}

impl DnsRoute {
    /// Creates a DNS-based route for the FQDN object group `group` with no gateway or
    /// interface.
    #[inline]
    #[must_use]
    pub fn new(group: &str) -> Self {
        Self {
            group: group.to_owned(),
            gateway: None,
            interface: None,
        }
    }
}

/// One typed DNS configuration mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is the vocabulary the Web, MCP and CLI front ends use"
)]
pub enum DnsChange {
    /// Add a DNS-over-TLS upstream.
    TlsUpstream(TlsUpstream),
    /// Add a DNS-over-HTTPS upstream.
    HttpsUpstream(HttpsUpstream),
    /// Select a filtering engine.
    FilterEngine(FilterEngine),
    /// Create a filtering profile.
    FilterProfile {
        /// Profile name.
        name: String,
    },
    /// Set a filtering profile description.
    FilterProfileDescription {
        /// Profile name.
        name: String,
        /// Profile description.
        description: String,
    },
    /// Assign a preset to a host MAC address.
    AssignHostPreset {
        /// Host MAC address.
        host: String,
        /// Preset name.
        preset: String,
    },
    /// Assign a profile to a host MAC address.
    AssignHostProfile {
        /// Host MAC address.
        host: String,
        /// Profile name.
        profile: String,
    },
    /// Assign a preset to an interface.
    AssignInterfacePreset {
        /// Interface name.
        interface: String,
        /// Preset name.
        preset: String,
    },
    /// Assign a profile to an interface.
    AssignInterfaceProfile {
        /// Interface name.
        interface: String,
        /// Profile name.
        profile: String,
    },
    /// Enable or disable global DNS interception.
    Intercept {
        /// Desired enabled state.
        enabled: bool,
    },
    /// Set DNS rebinding protection.
    RebindProtect(RebindProtection),
    /// Set or clear the maximum answer TTL.
    MaxTtl(Option<u32>),
    /// Add a DNS-based route.
    Route(DnsRoute),
    /// Add a plain DNS name server.
    NameServer {
        /// Resolver address.
        address: String,
    },
    /// Add a static DNS record.
    StaticHost {
        /// Domain name.
        domain: String,
        /// Resolved address.
        address: String,
    },
    /// Create an FQDN object group.
    FqdnGroup {
        /// Group name.
        name: String,
    },
    /// Set an FQDN object-group description.
    FqdnDescription {
        /// Group name.
        name: String,
        /// Group description.
        description: String,
    },
    /// Include a domain pattern in an FQDN object group.
    FqdnInclude {
        /// Group name.
        name: String,
        /// Included domain pattern.
        address: String,
    },
    /// Exclude a domain pattern from an FQDN object group.
    FqdnExclude {
        /// Group name.
        name: String,
        /// Excluded domain pattern.
        address: String,
    },
    /// Assign a `NextDNS` profile token to a host.
    NextDnsHost {
        /// Host MAC address.
        host: String,
        /// `NextDNS` profile token.
        token: u32,
    },
    /// Assign a `NextDNS` profile token to an interface.
    NextDnsInterface {
        /// Interface name.
        interface: String,
        /// `NextDNS` profile token.
        token: u32,
    },
}

/// DNS reads.
const READS: &[OperationDescriptor] = &[
    descriptor::read("dns_proxy", "show dns-proxy"),
    descriptor::read("running_configuration", "dns-proxy"),
    descriptor::read("nextdns", "nextdns"),
];

/// DNS writes.
const WRITES: &[OperationDescriptor] = &[
    descriptor::write("tls_upstream", "dns-proxy tls upstream"),
    descriptor::write("https_upstream", "dns-proxy https upstream"),
    descriptor::write("filter_engine", "dns-proxy filter engine"),
    descriptor::write("filter_profile", "dns-proxy filter profile"),
    descriptor::write("intercept", "dns-proxy intercept enable"),
    descriptor::write("rebind_protect", "dns-proxy rebind-protect"),
    descriptor::write("max_ttl", "dns-proxy max-ttl"),
    descriptor::write("route", "dns-proxy route object-group"),
    descriptor::write("name_server", "ip name-server"),
    descriptor::write("static_host", "ip host"),
    descriptor::write("fqdn_group", "object-group fqdn"),
    descriptor::write("nextdns_assign", "nextdns assign"),
];

/// DNS domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Dns,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads `show dns-proxy`.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_dns_proxy(router: &RouterCtx) -> Result<DnsProxyState> {
    read_show(&router.client, &["show", "dns-proxy"]).await
}

/// Reads the DNS-related running configuration.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`crate::DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_configuration(router: &RouterCtx) -> Result<DnsConfiguration> {
    let tree = serde_json::json!({
        "dns-proxy": {},
        "ip": {"host": {}, "name-server": {}},
        "object-group": {"fqdn": {}},
        "nextdns": {}
    });
    let response = router.client.show_rc(tree).await?;
    decode::value(
        router.client.log_id(),
        "show rc dns-proxy ip object-group nextdns",
        response.configuration_tree(),
    )
}

/// Plans one catalog-validated DNS mutation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`crate::DomainError::Validation`]).
#[inline]
pub fn plan_change(router: &RouterCtx, change: &DnsChange) -> Result<ChangeOp> {
    change::plan(router, change)
}

/// Converts a DNS plan into the only supported protected execution request.
///
/// # Errors
///
/// Returns [`crate::DomainError::InvalidCliToken`] when a request field is not one safe CLI word,
/// [`crate::DomainError::InvalidResponse`] when a request is not a DNS command, lacks a field, or a
/// command cannot be given a read-back of its own (a secret-bearing command, or a line that is not
/// exactly one configuration row), and [`crate::DomainError::Workflow`] when a rendered line does not
/// match its request.
#[inline]
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    change::request(operation)
}
