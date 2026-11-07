//! DNS proxy writes through the typed `DnsChange` planner.

use kcc_app::permissions::Permission;
use kcc_domain::dns::{
    self, DnsChange, DnsRoute, FilterEngine, HttpsUpstream, RebindProtection, TlsUpstream,
};

use super::{
    args_dom_dns::{DnsWriteCommand, EngineChoice, RebindChoice},
    args_dom_family::Family,
    args_domains_wire::DnsCommand,
    context::Ctx,
    dom_wire,
    domains::Session,
    exit::Outcome,
};

/// Runs a `dns` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn dns(ctx: &Ctx, command: Family<DnsCommand, DnsWriteCommand>) -> Outcome {
    match command {
        Family::Base(sub) => dom_wire::dns(ctx, sub).await,
        Family::Writes(sub) => dns_writes(ctx, sub).await,
    }
}

/// Runs a DNS write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn dns_writes(ctx: &Ctx, command: DnsWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let operation = dns::plan_change(session.router(), &change(command))?;
    session
        .cli(&operation, dns::change_request(&operation)?)
        .await
}

/// The typed DNS change of the command line.
fn change(command: DnsWriteCommand) -> DnsChange {
    match command {
        DnsWriteCommand::TlsUpstream {
            address,
            port,
            server_name,
            spki_hash,
            interface,
            domain,
        } => {
            let mut upstream = TlsUpstream::new(&address);
            upstream.port = port;
            upstream.server_name = server_name;
            upstream.spki_hash = spki_hash;
            upstream.interface = interface;
            upstream.domain = domain;
            DnsChange::TlsUpstream(upstream)
        }
        DnsWriteCommand::HttpsUpstream {
            url,
            format,
            hash,
            interface,
            domain,
        } => {
            let mut upstream = HttpsUpstream::new(&url);
            upstream.format = format;
            upstream.hash = hash;
            upstream.interface = interface;
            upstream.domain = domain;
            DnsChange::HttpsUpstream(upstream)
        }
        DnsWriteCommand::FilterEngine { engine } => DnsChange::FilterEngine(match engine {
            EngineChoice::Interceptor => FilterEngine::Interceptor,
            EngineChoice::Nextdns => FilterEngine::NextDns,
            EngineChoice::Opkg => FilterEngine::Opkg,
            EngineChoice::Public => FilterEngine::Public,
            EngineChoice::Skydns => FilterEngine::SkyDns,
        }),
        DnsWriteCommand::FilterProfile { name, description } => match description {
            Some(text) => DnsChange::FilterProfileDescription {
                name,
                description: text,
            },
            None => DnsChange::FilterProfile { name },
        },
        DnsWriteCommand::FilterAssign {
            host,
            interface,
            preset,
            profile,
        } => assignment((host, interface), (preset, profile)),
        DnsWriteCommand::Intercept { state } => DnsChange::Intercept {
            enabled: state.enabled(),
        },
        DnsWriteCommand::RebindProtect { mode } => DnsChange::RebindProtect(match mode {
            RebindChoice::Auto => RebindProtection::Auto,
            RebindChoice::Strict => RebindProtection::Strict,
        }),
        DnsWriteCommand::MaxTtl { seconds } => DnsChange::MaxTtl(seconds),
        DnsWriteCommand::Route {
            group,
            gateway,
            interface,
        } => {
            let mut route = DnsRoute::new(&group);
            route.gateway = gateway;
            route.interface = interface;
            DnsChange::Route(route)
        }
        DnsWriteCommand::NameServer { address } => DnsChange::NameServer { address },
        DnsWriteCommand::StaticHost { domain, address } => {
            DnsChange::StaticHost { domain, address }
        }
        DnsWriteCommand::FqdnGroup {
            name,
            description,
            include,
            exclude,
        } => fqdn(name, (description, include, exclude)),
        DnsWriteCommand::Nextdns {
            token,
            host,
            interface,
        } => host.map_or_else(
            || DnsChange::NextDnsInterface {
                interface: interface.unwrap_or_default(),
                token,
            },
            |mac| DnsChange::NextDnsHost { host: mac, token },
        ),
    }
}

/// A filtering assignment of `(preset, profile)` to `(host, interface)`; clap requires
/// exactly one of each pair.
fn assignment(
    (host, interface): (Option<String>, Option<String>),
    (preset, profile): (Option<String>, Option<String>),
) -> DnsChange {
    match (host, preset) {
        (Some(mac), Some(name)) => DnsChange::AssignHostPreset {
            host: mac,
            preset: name,
        },
        (Some(mac), None) => DnsChange::AssignHostProfile {
            host: mac,
            profile: profile.unwrap_or_default(),
        },
        (None, Some(name)) => DnsChange::AssignInterfacePreset {
            interface: interface.unwrap_or_default(),
            preset: name,
        },
        (None, None) => DnsChange::AssignInterfaceProfile {
            interface: interface.unwrap_or_default(),
            profile: profile.unwrap_or_default(),
        },
    }
}

/// An FQDN object-group change; clap allows at most one of the three options.
fn fqdn(
    name: String,
    (description, include, exclude): (Option<String>, Option<String>, Option<String>),
) -> DnsChange {
    match (description, include, exclude) {
        (Some(text), _, _) => DnsChange::FqdnDescription {
            name,
            description: text,
        },
        (None, Some(address), _) => DnsChange::FqdnInclude { name, address },
        (None, None, Some(address)) => DnsChange::FqdnExclude { name, address },
        (None, None, None) => DnsChange::FqdnGroup { name },
    }
}
