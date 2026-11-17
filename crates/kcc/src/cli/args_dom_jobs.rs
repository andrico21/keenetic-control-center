//! Configuration, diagnostics and component commands.

use clap::{Args, Subcommand};

use super::{args_domains_net::QueueChoice, args_fleet::FailsafeAction};

/// Configuration persistence commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ConfigCommand {
    /// Show unsaved changes, the last changing agent and the fail-safe timer.
    State,
    /// Save the running configuration.
    Save,
    /// Arm, commit or roll back the router's fail-safe timer.
    Failsafe {
        /// What to do.
        action: FailsafeAction,
        /// Timer length when arming, 300..=3600 seconds.
        #[arg(long, default_value_t = 900)]
        seconds: u64,
    },
    /// Restart the countdown of the router's armed fail-safe timer.
    KeepAlive,
}

/// What to probe and how; options a tool does not know are refused before sending.
#[derive(Debug, Clone, Args)]
#[non_exhaustive]
pub struct ProbeArgs {
    /// Host name or address to probe.
    pub target: String,
    /// Number of probes.
    #[arg(long)]
    pub count: Option<u32>,
    /// Probe size in bytes (ping, ping6, traceroute).
    #[arg(long)]
    pub packet_size: Option<u32>,
    /// Interface to send from (required by arping).
    #[arg(long)]
    pub source_interface: Option<String>,
    /// Seconds to wait for each answer (arping, traceroute).
    #[arg(long)]
    pub wait_time: Option<u32>,
    /// Destination port (traceroute, iperf3).
    #[arg(long)]
    pub port: Option<u16>,
    /// Test length in seconds (iperf3).
    #[arg(long)]
    pub time: Option<u32>,
}

/// Diagnostic jobs; each waits for the router's answer and prints its lines.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum DiagnosticsCommand {
    /// IPv4 ping.
    Ping(ProbeArgs),
    /// IPv6 ping.
    Ping6(ProbeArgs),
    /// Trace the route to a host.
    Traceroute(ProbeArgs),
    /// Address-resolution ping on the LAN.
    Arping(ProbeArgs),
    /// Throughput test against an iperf3 server.
    Iperf3(ProbeArgs),
}

/// Component commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ComponentsCommand {
    /// Installed and available components.
    List,
    /// The staged changes.
    Pending,
    /// Ask the update server for news.
    CheckUpdate,
    /// Stage an installation or removal.
    Queue {
        /// What to stage.
        action: QueueChoice,
        /// Component name.
        component: String,
    },
    /// Install the staged changes and reboot (destructive); waits for the router.
    Commit,
    /// Set the automatic update channel.
    AutoUpdateChannel {
        /// Channel name, e.g. `stable`.
        channel: String,
    },
    /// Set the schedule of automatic updates.
    AutoUpdateSchedule {
        /// Schedule name.
        schedule: String,
    },
}
