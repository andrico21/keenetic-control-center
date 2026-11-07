//! Commands that run as jobs or keep a timer alive: diagnostics, the component commit
//! and auto-update, and the fail-safe keep-alive.

use clap::{Args, Subcommand};

/// More configuration commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ConfigWriteCommand {
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
pub enum DiagnosticsWriteCommand {
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

/// More component commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ComponentsWriteCommand {
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
