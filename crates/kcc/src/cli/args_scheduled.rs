//! `kcc scheduled` commands: weekly scheduled actions.

use clap::{ArgGroup, Args, Subcommand};

/// Weekly scheduled actions, run by `kcc serve` (or once now with `run-now`).
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ScheduledCommand {
    /// List the scheduled actions.
    List,
    /// Show one scheduled action, its next run and its last runs.
    Show {
        /// Schedule id.
        id: String,
    },
    /// Add a scheduled action on `--router`, owned by the CLI user.
    Add(ScheduledAddArgs),
    /// Change a scheduled action; what is not given stays. The CLI user becomes its owner.
    Edit {
        /// Schedule id.
        id: String,
        /// The changes.
        #[command(flatten)]
        changes: ScheduledEditArgs,
    },
    /// Pause a scheduled action: its slots do not run until it is resumed.
    Pause {
        /// Schedule id.
        id: String,
    },
    /// Resume a paused scheduled action; the CLI user becomes its owner.
    Resume {
        /// Schedule id.
        id: String,
    },
    /// Delete a scheduled action and its run history.
    Delete {
        /// Schedule id.
        id: String,
    },
    /// Run a scheduled action once now, in this process, as its owner; a busy router is
    /// not tried again and no Telegram message is sent.
    RunNow {
        /// Schedule id.
        id: String,
    },
}

/// A new scheduled action.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("action")
        .required(true)
        .args(["policy_switch", "preset", "backup", "reboot"])
))]
#[non_exhaustive]
pub struct ScheduledAddArgs {
    /// Name, unique on the router: 1 to 64 characters.
    #[arg(long)]
    pub name: String,
    /// Weekdays, comma-separated: mon, tue, wed, thu, fri, sat, sun.
    #[arg(long, value_name = "DAYS")]
    pub days: String,
    /// Local time of day, `HH:MM` (00:00 to 23:59).
    #[arg(long, value_name = "HH:MM")]
    pub at: String,
    /// IANA time zone, e.g. `Europe/Berlin` (default: `[schedules] default_timezone`).
    #[arg(long, value_name = "ZONE")]
    pub tz: Option<String>,
    /// What runs.
    #[command(flatten)]
    pub action: ScheduledActionArgs,
}

/// Changes to a scheduled action.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("action")
        .required(false)
        .args(["policy_switch", "preset", "backup", "reboot"])
))]
#[non_exhaustive]
pub struct ScheduledEditArgs {
    /// New name: 1 to 64 characters.
    #[arg(long)]
    pub name: Option<String>,
    /// New weekdays, comma-separated: mon, tue, wed, thu, fri, sat, sun.
    #[arg(long, value_name = "DAYS")]
    pub days: Option<String>,
    /// New local time of day, `HH:MM`.
    #[arg(long, value_name = "HH:MM")]
    pub at: Option<String>,
    /// New IANA time zone.
    #[arg(long, value_name = "ZONE")]
    pub tz: Option<String>,
    /// A new action; without one the action stays.
    #[command(flatten)]
    pub action: ScheduledActionArgs,
}

/// The action of a scheduled action: exactly one of the four.
#[derive(Debug, Args)]
#[group(skip)]
#[non_exhaustive]
pub struct ScheduledActionArgs {
    /// A client policy switch.
    #[command(flatten)]
    pub switch: ScheduledSwitchArgs,
    /// A preset apply.
    #[command(flatten)]
    pub preset: ScheduledPresetArgs,
    /// Back up the startup configuration.
    #[arg(long)]
    pub backup: bool,
    /// Restart the router (needs `--confirm-destructive <router-id>`).
    #[arg(long)]
    pub reboot: bool,
}

/// A client policy switch.
#[derive(Debug, Args)]
#[group(skip)]
#[non_exhaustive]
pub struct ScheduledSwitchArgs {
    /// Put one registered client under a connection policy (with `--mac` and `--policy`).
    #[arg(long, requires_all = ["mac", "policy"])]
    pub policy_switch: bool,
    /// The client's MAC address.
    #[arg(long, requires = "policy_switch")]
    pub mac: Option<String>,
    /// The connection policy's name.
    #[arg(long, requires = "policy_switch")]
    pub policy: Option<String>,
}

/// A preset apply.
#[derive(Debug, Args)]
#[group(skip)]
#[non_exhaustive]
pub struct ScheduledPresetArgs {
    /// Apply this stored preset in Merge mode; the changes stay unsaved.
    #[arg(long, value_name = "ID")]
    pub preset: Option<String>,
    /// Acknowledge that the router runs a documentation-based firmware line.
    #[arg(long, requires = "preset")]
    pub ack_documentation_tier: bool,
}
