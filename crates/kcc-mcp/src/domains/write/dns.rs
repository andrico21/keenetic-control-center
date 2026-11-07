//! `kcc_dns_write`.

use kcc_domain::dns::{self, DnsChange, FilterEngine, HttpsUpstream, RebindProtection};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::common::{apply_cli, check_op, needed, open, text};
use crate::{KccMcp, McpFailure, domains::table::Area, support::route::parse};

/// DNS write operations. `tls_upstream` and `route` are not offered: their domain inputs
/// have no public constructor.
pub(super) const DNS_OPS: &[&str] = &[
    "https_upstream",
    "filter_engine",
    "filter_profile",
    "intercept",
    "rebind_protect",
    "max_ttl",
    "name_server",
    "static_host",
    "fqdn_group",
    "nextdns_assign",
];

/// Arguments of `kcc_dns_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DnsInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Profile, group, or domain name.
    #[serde(default)]
    name: Option<String>,
    /// Upstream URL, filter engine, or rebind mode (`auto` or `strict`).
    #[serde(default)]
    value: Option<String>,
    /// Address for `name_server`, `static_host`, and `fqdn_group`.
    #[serde(default)]
    address: Option<String>,
    /// Description for `filter_profile` and `fqdn_group`.
    #[serde(default)]
    description: Option<String>,
    /// Client host for profile or `NextDNS` assignment.
    #[serde(default)]
    client: Option<String>,
    /// Interface for profile assignment, upstream binding, or `NextDNS`.
    #[serde(default)]
    interface: Option<String>,
    /// Filter preset for an assignment.
    #[serde(default)]
    preset: Option<String>,
    /// Filter profile for an assignment.
    #[serde(default)]
    profile: Option<String>,
    /// Flag for `intercept`; for `fqdn_group` with `address`, excludes instead of includes.
    #[serde(default)]
    enabled: Option<bool>,
    /// Maximum TTL (absent clears it) or `NextDNS` token.
    #[serde(default)]
    number: Option<u32>,
}

/// An owned bounded text argument.
fn owned(value: Option<&str>) -> Result<String, McpFailure> {
    text(value).map(str::to_owned)
}

/// Assigns a preset or profile to a client host or interface.
fn assignment(input: &DnsInput) -> Result<DnsChange, McpFailure> {
    let preset = input
        .preset
        .as_deref()
        .map(|value| owned(Some(value)))
        .transpose()?;
    Ok(match (input.client.as_deref(), preset) {
        (Some(host), Some(preset)) => DnsChange::AssignHostPreset {
            host: owned(Some(host))?,
            preset,
        },
        (Some(host), None) => DnsChange::AssignHostProfile {
            host: owned(Some(host))?,
            profile: owned(input.profile.as_deref())?,
        },
        (None, Some(preset)) => DnsChange::AssignInterfacePreset {
            interface: owned(input.interface.as_deref())?,
            preset,
        },
        (None, None) => DnsChange::AssignInterfaceProfile {
            interface: owned(input.interface.as_deref())?,
            profile: owned(input.profile.as_deref())?,
        },
    })
}

/// Builds the curated DNS change of `input`.
fn change(input: &DnsInput) -> Result<DnsChange, McpFailure> {
    let name = || owned(input.name.as_deref());
    let address = || owned(input.address.as_deref());
    Ok(match input.op.as_str() {
        "https_upstream" => {
            let mut upstream = HttpsUpstream::new(text(input.value.as_deref())?);
            upstream.interface.clone_from(&input.interface);
            DnsChange::HttpsUpstream(upstream)
        }
        "filter_engine" => DnsChange::FilterEngine(match text(input.value.as_deref())? {
            "interceptor" => FilterEngine::Interceptor,
            "nextdns" => FilterEngine::NextDns,
            "opkg" => FilterEngine::Opkg,
            "public" => FilterEngine::Public,
            "skydns" => FilterEngine::SkyDns,
            _ => return Err(McpFailure::InvalidArguments),
        }),
        "filter_profile" if input.preset.is_some() || input.profile.is_some() => assignment(input)?,
        "filter_profile" => match input.description.as_deref() {
            Some(description) => DnsChange::FilterProfileDescription {
                name: name()?,
                description: owned(Some(description))?,
            },
            None => DnsChange::FilterProfile { name: name()? },
        },
        "intercept" => DnsChange::Intercept {
            enabled: needed(input.enabled)?,
        },
        "rebind_protect" => DnsChange::RebindProtect(match text(input.value.as_deref())? {
            "auto" => RebindProtection::Auto,
            "strict" => RebindProtection::Strict,
            _ => return Err(McpFailure::InvalidArguments),
        }),
        "max_ttl" => DnsChange::MaxTtl(input.number),
        "name_server" => DnsChange::NameServer {
            address: address()?,
        },
        "static_host" => DnsChange::StaticHost {
            domain: name()?,
            address: address()?,
        },
        "fqdn_group" => match (input.address.as_deref(), input.description.as_deref()) {
            (Some(_), _) if input.enabled == Some(false) => DnsChange::FqdnExclude {
                name: name()?,
                address: address()?,
            },
            (Some(_), _) => DnsChange::FqdnInclude {
                name: name()?,
                address: address()?,
            },
            (None, Some(description)) => DnsChange::FqdnDescription {
                name: name()?,
                description: owned(Some(description))?,
            },
            (None, None) => DnsChange::FqdnGroup { name: name()? },
        },
        _ => {
            let token = needed(input.number)?;
            match input.client.as_deref() {
                Some(host) => DnsChange::NextDnsHost {
                    host: owned(Some(host))?,
                    token,
                },
                None => DnsChange::NextDnsInterface {
                    interface: owned(input.interface.as_deref())?,
                    token,
                },
            }
        }
    })
}

/// Runs one DNS write.
pub(super) async fn dns(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: DnsInput = parse(arguments)?;
    check_op(DNS_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Dns,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let planned = dns::plan_change(&opened.2, &change(&input)?);
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, dns::change_request),
    )
    .await
}
