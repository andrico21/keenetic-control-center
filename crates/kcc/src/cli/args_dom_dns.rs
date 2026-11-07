//! DNS write commands: one subcommand per `DnsChange` family, with explicit flags.

use clap::{ArgGroup, Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// DNS filtering engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum EngineChoice {
    /// Built-in interception.
    Interceptor,
    /// `NextDNS`.
    Nextdns,
    /// A package-provided engine.
    Opkg,
    /// Public resolvers.
    Public,
    /// `SkyDNS`.
    Skydns,
}

/// DNS rebinding protection modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum RebindChoice {
    /// Let the router choose.
    Auto,
    /// Strict protection.
    Strict,
}

/// DNS proxy commands that change the configuration.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DnsWriteCommand {
    /// Add a DNS-over-TLS upstream.
    TlsUpstream {
        /// Resolver IP address.
        address: String,
        /// Resolver port.
        #[arg(long)]
        port: Option<u16>,
        /// TLS server name.
        #[arg(long)]
        server_name: Option<String>,
        /// SPKI hash.
        #[arg(long)]
        spki_hash: Option<String>,
        /// Use the resolver only through this interface.
        #[arg(long)]
        interface: Option<String>,
        /// Use the resolver only for this DNS suffix.
        #[arg(long)]
        domain: Option<String>,
    },
    /// Add a DNS-over-HTTPS upstream.
    HttpsUpstream {
        /// Resolver URL.
        url: String,
        /// Response format, `dnsm` or `json`.
        #[arg(long)]
        format: Option<String>,
        /// SNI/SPKI hash.
        #[arg(long)]
        hash: Option<String>,
        /// Use the resolver only through this interface.
        #[arg(long)]
        interface: Option<String>,
        /// Use the resolver only for this DNS suffix.
        #[arg(long)]
        domain: Option<String>,
    },
    /// Select the filtering engine.
    FilterEngine {
        /// Engine.
        #[arg(value_enum)]
        engine: EngineChoice,
    },
    /// Create a filtering profile, or describe it with `--description`.
    FilterProfile {
        /// Profile name.
        name: String,
        /// Description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Assign a filtering preset or profile to a host or an interface.
    #[command(group = ArgGroup::new("who").required(true).multiple(false))]
    #[command(group = ArgGroup::new("what").required(true).multiple(false))]
    FilterAssign {
        /// Host MAC address.
        #[arg(long, group = "who")]
        host: Option<String>,
        /// Interface name.
        #[arg(long, group = "who")]
        interface: Option<String>,
        /// Preset name.
        #[arg(long, group = "what")]
        preset: Option<String>,
        /// Profile name.
        #[arg(long, group = "what")]
        profile: Option<String>,
    },
    /// Intercept every DNS query of the LAN.
    Intercept {
        /// On or off.
        state: Toggle,
    },
    /// Set DNS rebinding protection.
    RebindProtect {
        /// Mode.
        #[arg(value_enum)]
        mode: RebindChoice,
    },
    /// Set the longest answer TTL, or clear it when no value is given.
    MaxTtl {
        /// Seconds.
        seconds: Option<u32>,
    },
    /// Route the addresses of an FQDN object group.
    Route {
        /// FQDN object-group name.
        group: String,
        /// Gateway keyword.
        #[arg(long)]
        gateway: Option<String>,
        /// Egress interface.
        #[arg(long)]
        interface: Option<String>,
    },
    /// Add a plain DNS server.
    NameServer {
        /// Server address.
        address: String,
    },
    /// Add a static DNS record.
    StaticHost {
        /// Domain name.
        domain: String,
        /// Address.
        address: String,
    },
    /// Create an FQDN object group, describe it, or include or exclude a domain.
    #[command(group = ArgGroup::new("member").multiple(false))]
    FqdnGroup {
        /// Group name.
        name: String,
        /// Description.
        #[arg(long, group = "member")]
        description: Option<String>,
        /// Domain pattern to include.
        #[arg(long, group = "member")]
        include: Option<String>,
        /// Domain pattern to exclude.
        #[arg(long, group = "member")]
        exclude: Option<String>,
    },
    /// Assign a `NextDNS` profile to a host or an interface.
    #[command(group = ArgGroup::new("who").required(true).multiple(false))]
    Nextdns {
        /// `NextDNS` profile number.
        #[arg(long)]
        token: u32,
        /// Host MAC address.
        #[arg(long, group = "who")]
        host: Option<String>,
        /// Interface name.
        #[arg(long, group = "who")]
        interface: Option<String>,
    },
}
