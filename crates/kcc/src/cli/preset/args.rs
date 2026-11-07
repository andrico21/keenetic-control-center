//! Preset and settings-copy commands.

use clap::{Args, Subcommand, ValueEnum};

/// Settings presets: groups of settings captured from one router and applied to another.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum PresetCommand {
    /// List the stored presets.
    List,
    /// Show one preset; secrets stay redacted unless `--reveal` (audited).
    Show {
        /// Preset id.
        id: String,
        /// Print secret values (needs the `RevealSecrets` permission).
        #[arg(long)]
        reveal: bool,
    },
    /// Capture settings groups into a stored, encrypted preset.
    Capture {
        /// `<router-id>`, `backup:<router>/<name>` or `file:<path>`.
        #[arg(long, value_name = "SOURCE")]
        from: String,
        /// Settings group ids, comma-separated (e.g. `dns-secure`).
        #[arg(long, value_delimiter = ',', required = true)]
        groups: Vec<String>,
        /// Preset id: letters, digits, `-` and `_`.
        #[arg(long)]
        name: String,
        /// Optional description.
        #[arg(long, default_value_t = String::new())]
        description: String,
    },
    /// Delete a stored preset.
    Delete {
        /// Preset id.
        id: String,
    },
    /// Print the plan of applying a preset onto `--router`; nothing is written.
    Plan {
        /// Preset id.
        id: String,
        /// Planning choices.
        #[command(flatten)]
        options: ApplyOptions,
    },
    /// Apply a preset onto `--router` under its fail-safe timer.
    Apply {
        /// Preset id.
        id: String,
        /// Planning choices.
        #[command(flatten)]
        options: ApplyOptions,
        /// How the run ends after verification; required without a terminal.
        #[arg(long, value_enum)]
        finish: Option<Finish>,
    },
    /// Finish a run started elsewhere (its job id).
    Finish {
        /// Run (job) id printed when the run started.
        run_id: String,
        /// How the run ends.
        #[arg(value_enum)]
        action: Finish,
    },
}

/// Choices shared by planning, applying and copying.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ApplyOptions {
    /// `merge` keeps target-only settings; `mirror` removes them from the copied groups.
    #[arg(long, value_enum, default_value_t = Mode::Merge)]
    pub mode: Mode,
    /// Copy captured WireGuard private keys instead of generating new ones on the target.
    #[arg(long)]
    pub keep_wireguard_keys: bool,
    /// Acknowledge a target firmware supported from documentation only.
    #[arg(long)]
    pub ack_documentation_tier: bool,
    /// Plan item numbers to leave out, comma-separated.
    #[arg(long, value_delimiter = ',', value_name = "N,..")]
    pub exclude: Vec<usize>,
}

/// How target settings in the copied groups are reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Mode {
    /// Add or update; keep settings only the target has.
    Merge,
    /// Add or update, then remove settings only the target has.
    Mirror,
}

/// How an applied and verified run ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Finish {
    /// Stop the fail-safe timer and keep the changes unsaved.
    KeepUnsaved,
    /// Save the changes to the startup configuration.
    Save,
    /// Restore the configuration from before the run.
    Rollback,
}

/// `kcc copy`: copy settings groups from one router, backup or file onto a router.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CopyCommand {
    /// `<router-id>`, `backup:<router>/<name>` or `file:<path>`.
    #[arg(long, value_name = "SOURCE")]
    pub from: String,
    /// Target router id.
    #[arg(long, value_name = "ROUTER-ID")]
    pub to: String,
    /// Settings group ids, comma-separated (e.g. `dns-secure`).
    #[arg(long, value_delimiter = ',', required = true)]
    pub groups: Vec<String>,
    /// Planning choices.
    #[command(flatten)]
    pub options: ApplyOptions,
    /// How the copy ends after verification; required without a terminal.
    #[arg(long, value_enum)]
    pub finish: Option<Finish>,
}
