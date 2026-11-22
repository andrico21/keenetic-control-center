//! Entware commands: status, the guided setup, the `opkg` settings and the removal.

use clap::{Subcommand, ValueEnum};

use super::args_domains::Toggle;

/// Entware commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum EntwareCommand {
    /// Whether the router can run Entware, its settings and the drives it can use.
    Status,
    /// Install Entware on a drive (destructive); runs as a job and leaves the
    /// configuration unsaved.
    Setup {
        /// The drive: an eligible drive's disk argument (`<label>:/` or `<uuid>:/`, see
        /// `kcc entware status`) or `internal` for the router's internal storage.
        #[arg(long, value_name = "DISK-ARG|internal")]
        drive: String,
        /// The installer; required when the router reports the `mips` architecture.
        #[arg(long, value_enum)]
        arch: Option<ArchChoice>,
    },
    /// Change one Entware setting.
    #[command(subcommand)]
    Set(EntwareSetting),
    /// Stop running Entware from its drive (destructive).
    Remove,
}

/// Entware settings.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum EntwareSetting {
    /// Run the init scripts with root `/opt` (stops SSH management while on).
    Chroot {
        /// On or off.
        state: Toggle,
    },
    /// The time zone of the Entware environment.
    Timezone {
        /// `auto` or a time zone name.
        value: String,
    },
    /// The init script the router runs as root from the drive (destructive).
    Initrc {
        /// A path under `/opt/`.
        path: String,
    },
    /// Hand port 53 to Entware (management change; needs `--yes`).
    DnsOverride {
        /// On or off.
        state: Toggle,
    },
}

/// The Entware installers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ArchChoice {
    /// 64-bit ARM.
    Aarch64,
    /// Little-endian MIPS.
    Mipsel,
    /// Big-endian MIPS.
    Mips,
}
