//! Entware over SSH: the enrolment, the packages and the services.
//!
//! Every command needs `Destructive` on the router and `--confirm-destructive <router-id>`
//! (reads included). No command takes a password, a key or command text as an argument.

use clap::{Args, Subcommand};

/// Entware SSH enrolment commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum EntwareSshCommand {
    /// Switch SSH management of Entware on, optionally on another port (default 222).
    Enable {
        /// The Entware SSH port.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
    },
    /// Forget kcc's SSH key and pin locally; kcc's key line stays on the router.
    Disable,
    /// Read the Entware host key without signing in; prints its fingerprint and a
    /// single-use ticket.
    Probe,
    /// Enrol with a confirmed probe: the Entware root password comes from
    /// `--password-file`, else `KCC_PASSWORD`, else a hidden prompt.
    Bootstrap(ConfirmedProbe),
    /// Pin a changed Entware host key with a confirmed probe, as `bootstrap`.
    Repin(ConfirmedProbe),
    /// Remove kcc's key line from the router, then the local state.
    Revoke,
}

/// The probe an admin confirmed.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ConfirmedProbe {
    /// The ticket `kcc entware ssh probe` printed (64 hexadecimal digits).
    #[arg(long, value_name = "TICKET")]
    pub ticket: String,
    /// The host key fingerprint you checked out of band (`SHA256:...`).
    #[arg(long, value_name = "SHA256:...")]
    pub fingerprint: String,
}

/// Entware package commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum PackagesCommand {
    /// The installed packages.
    List,
    /// The installed packages that have an upgrade.
    Upgradable,
    /// Update the package lists.
    Update,
    /// Install a package.
    Install {
        /// The package name.
        name: String,
    },
    /// Remove an installed package.
    Remove {
        /// The package name.
        name: String,
    },
    /// Upgrade an installed package.
    Upgrade {
        /// The package name.
        name: String,
    },
}

/// Entware service commands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum EntwareServicesCommand {
    /// The init scripts in `/opt/etc/init.d`.
    List,
    /// Whether a service runs.
    Status {
        /// The init script name, e.g. `S51dropbear`.
        name: String,
    },
    /// Start a service.
    Start {
        /// The init script name.
        name: String,
    },
    /// Stop a service.
    Stop {
        /// The init script name.
        name: String,
    },
    /// Restart a service.
    Restart {
        /// The init script name.
        name: String,
    },
    /// The router's log records of a service's process.
    Log {
        /// The init script name.
        name: String,
        /// How many of the newest records to print.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
        lines: u32,
    },
}
