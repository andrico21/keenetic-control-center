//! DNS proxy commands: the reads, and the writes through the typed `DnsChange` planner.

use kcc_app::permissions::Permission;
use kcc_domain::dns::{
    self, DnsChange, DnsRoute, FilterEngine, HttpsUpstream, RebindProtection, TlsUpstream,
};

use super::{
    args_dom_dns::{DnsCommand, EngineChoice, RebindChoice},
    context::Ctx,
    domains::Session,
    exit::Outcome,
};

/// What a `dns` command asks for.
enum Request {
    /// The DNS proxy state.
    Proxy,
    /// The configured resolvers, records and lists.
    Config,
    /// A typed configuration change.
    Change(DnsChange),
}

/// Runs a `dns` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn dns(ctx: &Ctx, command: DnsCommand) -> Outcome {
    let change = match request(command) {
        Request::Proxy => {
            let session = Session::open(ctx, Permission::Read).await?;
            return session.show(&dns::read_dns_proxy(session.router()).await?);
        }
        Request::Config => {
            let session = Session::open(ctx, Permission::Read).await?;
            return session.show(&dns::read_configuration(session.router()).await?);
        }
        Request::Change(change) => change,
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let operation = dns::plan_change(session.router(), &change)?;
    session
        .cli(&operation, dns::change_request(&operation)?)
        .await
}

/// What `command` asks for: a read, or the typed DNS change.
fn request(command: DnsCommand) -> Request {
    let change = match command {
        DnsCommand::Proxy => return Request::Proxy,
        DnsCommand::Config => return Request::Config,
        DnsCommand::TlsUpstream {
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
        DnsCommand::HttpsUpstream {
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
        DnsCommand::FilterEngine { engine } => DnsChange::FilterEngine(match engine {
            EngineChoice::Interceptor => FilterEngine::Interceptor,
            EngineChoice::Nextdns => FilterEngine::NextDns,
            EngineChoice::Opkg => FilterEngine::Opkg,
            EngineChoice::Public => FilterEngine::Public,
            EngineChoice::Skydns => FilterEngine::SkyDns,
        }),
        DnsCommand::FilterProfile { name, description } => match description {
            Some(text) => DnsChange::FilterProfileDescription {
                name,
                description: text,
            },
            None => DnsChange::FilterProfile { name },
        },
        DnsCommand::FilterAssign {
            host,
            interface,
            preset,
            profile,
        } => assignment((host, interface), (preset, profile)),
        DnsCommand::Intercept { state } => DnsChange::Intercept {
            enabled: state.enabled(),
        },
        DnsCommand::RebindProtect { mode } => DnsChange::RebindProtect(match mode {
            RebindChoice::Auto => RebindProtection::Auto,
            RebindChoice::Strict => RebindProtection::Strict,
        }),
        DnsCommand::MaxTtl { seconds } => DnsChange::MaxTtl(seconds),
        DnsCommand::Route {
            group,
            gateway,
            interface,
        } => {
            let mut route = DnsRoute::new(&group);
            route.gateway = gateway;
            route.interface = interface;
            DnsChange::Route(route)
        }
        DnsCommand::NameServer { address } => DnsChange::NameServer { address },
        DnsCommand::StaticHost { domain, address } => DnsChange::StaticHost { domain, address },
        DnsCommand::FqdnGroup {
            name,
            description,
            include,
            exclude,
        } => fqdn(name, (description, include, exclude)),
        DnsCommand::Nextdns {
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
    };
    Request::Change(change)
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
