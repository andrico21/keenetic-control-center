//! Migration commands.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

/// Migration onto the router named by `--router` (the target).
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum MigrateCommand {
    /// Print the target's hardware and interface inventory.
    Inventory,
    /// Plan a migration and write the reviewed plan file.
    Plan {
        /// Source and planning choices.
        #[command(flatten)]
        input: PlanInput,
        /// Where to write the plan (JSON, secrets redacted).
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// Apply a reviewed plan under the router's fail-safe timer.
    Apply {
        /// Source and planning choices; they must reproduce the plan file.
        #[command(flatten)]
        input: PlanInput,
        /// The plan file written by `kcc migrate plan`.
        #[arg(long, value_name = "PATH")]
        plan: PathBuf,
        /// Finish right after applying: commit, roll back, or keep the timer running.
        #[arg(long, value_enum, default_value_t = FinishAction::Keep)]
        finish: FinishAction,
        /// Fail-safe timer, 300..=3600 seconds.
        #[arg(long, default_value_t = 900)]
        safety_seconds: u64,
        /// Write the apply report (JSON) to this file.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
    /// Finish a kept migration: commit it or roll it back.
    Finish {
        /// What to do.
        action: FinishStep,
    },
    /// Write the human-readable report of a plan.
    Report {
        /// Source and planning choices.
        #[command(flatten)]
        input: PlanInput,
        /// Report format.
        #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
        format: ReportFormat,
        /// Write to this file instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
    },
}

/// Where the source configuration comes from and the planner's answers.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct PlanInput {
    /// `<router-id>` (or `router:<id>`), `backup:<router>/<name>` or `file:<path>`.
    #[arg(long, value_name = "SOURCE")]
    pub from: String,
    /// Acknowledge a target firmware supported from documentation only.
    #[arg(long)]
    pub ack_documentation_tier: bool,
    /// Confirmed URL to reconnect at after a management change.
    #[arg(long, value_name = "URL")]
    pub reconnect_url: Option<String>,
    /// New password of a router user as `<user>=<file>`; repeat for several.
    #[arg(long = "user-password", value_name = "USER=FILE")]
    pub user_passwords: Vec<String>,
}

/// How `migrate apply` ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum FinishAction {
    /// Keep the changes and stop the timer.
    Commit,
    /// Restore the previous configuration.
    Rollback,
    /// Leave the timer running; finish later with `kcc migrate finish`.
    Keep,
}

/// How `migrate finish` ends a kept migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum FinishStep {
    /// Keep the changes.
    Commit,
    /// Restore the previous configuration now.
    Rollback,
}

/// Report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ReportFormat {
    /// Markdown.
    Markdown,
    /// JSON.
    Json,
    /// HTML.
    Html,
}
