//! Project gates and generators for keenetic-control-center, run as `cargo xtask <command>`.
//!
//! Every gate writes its report through [`std::io::Write`] and maps its verdict to the
//! process exit code: 0 when the gate passes, 1 when it fails, 2 when it could not run.

extern crate alloc;

mod allow_gate;
mod assets;
mod cancel_safety;
mod cargo_lints;
mod catalog;
mod catalog_build;
mod catalog_extract;
mod catalog_fetch;
mod failure;
mod i18n;
mod lint_completeness;
mod lint_inheritance;
mod manifest;
mod metric_docs;
mod profile_eq;
mod seccomp;
mod seccomp_gen;
mod seccomp_groups;
mod tool_docs;
mod tool_output;

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};

use crate::failure::GateError;

/// Project gates and generators for keenetic-control-center.
#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    /// Repository root (defaults to the parent of the xtask manifest directory).
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// The task to run.
    #[command(subcommand)]
    command: Task,
}

/// One xtask subcommand. Later gates and generators are added as new variants.
#[derive(Debug, Clone, Subcommand)]
enum Task {
    /// Check that the lint profile covers every allow-by-default rustc lint, every
    /// Clippy `restriction` lint and every Cargo lint outside the denied groups, except
    /// the documented exclusions.
    LintCompleteness,
    /// Fail on any `#[allow(` or `#![allow(` attribute under `crates/` and `xtask/src`.
    AllowGate,
    /// Fail when the xtask `[lints]` tables differ from the root `[workspace.lints]`, or a
    /// workspace member lacks `[lints] workspace = true`.
    ProfileEq,
    /// Fail when a non-test fully `pub` async fn under `crates/*/src` lacks a
    /// `// cancel-safe:` or `// NOT cancel-safe:` comment.
    CancelSafety,
    /// Fetch and extract the official CLI reference manuals into `catalog/.cache/`.
    #[command(subcommand)]
    Catalog(CatalogTask),
    /// Regenerate `crates/kcc-i18n/src/keys.rs` from `locales/en/*.ftl`.
    #[command(name = "i18n-gen")]
    I18nGen,
    /// Check every locale against the English catalog: same keys, same variables, no
    /// empty values, valid Fluent syntax, and an up-to-date `keys.rs`.
    #[command(name = "i18n-check")]
    I18nCheck {
        /// Catalog directory to check instead of `crates/kcc-i18n/locales`.
        #[arg(long)]
        locales_dir: Option<PathBuf>,
    },
    /// Check the vendored Web UI assets against `ASSETS.lock` (hashes, licenses, no
    /// unpinned file) and that no template loads an unpinned or foreign asset.
    #[command(name = "assets-check")]
    AssetsCheck {
        /// Asset directory to check instead of `crates/kcc-web/assets`.
        #[arg(long)]
        assets_dir: Option<PathBuf>,
    },
    /// Regenerate `docs/METRICS.md` from the kcc-telemetry metric catalogue.
    #[command(name = "gen-metric-docs")]
    GenMetricDocs,
    /// Regenerate `docs/MCP_TOOLS.md` from the kcc-mcp tool registry.
    #[command(name = "gen-tool-docs")]
    GenToolDocs,
    /// Derive the container seccomp allowlist by tracing the static musl binary.
    #[command(subcommand)]
    Seccomp(SeccompTask),
}

/// One `seccomp` subcommand.
#[derive(Debug, Clone, Subcommand)]
enum SeccompTask {
    /// Run the musl `kcc` natively under `strace -f` while `deploy/podman/e2e.sh` drives
    /// every I/O path (needs `strace`).
    Trace {
        /// The static binary (default `<target>/<arch>-unknown-linux-musl/release/kcc`).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Trace directory (default `<target>/seccomp-trace`), emptied first.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Union the traces and the runtime exec prologue into
    /// `deploy/podman/seccomp-kcc.json`; an unmapped syscall fails.
    Gen {
        /// Trace directory (default `<target>/seccomp-trace`).
        #[arg(long)]
        traces: Option<PathBuf>,
        /// Compare with the committed profile instead of writing it.
        #[arg(long)]
        check: bool,
    },
}

/// One `catalog` subcommand.
#[derive(Debug, Clone, Subcommand)]
enum CatalogTask {
    /// Download the CLI manual of every model for one firmware version and write
    /// `catalog/sources.lock`. A 404 records the model as absent and is not a failure.
    Fetch {
        /// Firmware version, for example `5.1`.
        #[arg(long)]
        version: String,
        /// Model list overriding `catalog/sources.toml`.
        #[arg(long)]
        models: Option<PathBuf>,
    },
    /// Run `pdftotext` and read the PDF bookmarks of every cached manual.
    Extract,
    /// Parse extracted manuals and generate one committed firmware catalog.
    Build {
        /// Firmware version: `4.3`, `5.0`, or `5.1`.
        #[arg(long)]
        version: String,
    },
}

/// Outcome of a gate that ran to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The gate found nothing to report.
    Pass,
    /// The gate found violations and printed them.
    Fail,
}

/// Exit code for a gate that could not run (I/O, parse or subprocess error).
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = io::stdout().lock();
    match run(&cli, &mut stdout) {
        Ok(Verdict::Pass) => ExitCode::SUCCESS,
        Ok(Verdict::Fail) => ExitCode::FAILURE,
        Err(err) => match writeln!(io::stderr(), "xtask: {err}") {
            Ok(()) | Err(_) => ExitCode::from(EXIT_ERROR),
        },
    }
}

/// Dispatches the parsed command line to its gate.
///
/// # Errors
///
/// Returns the gate's error when it cannot run to a verdict.
fn run<W>(cli: &Cli, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let root = match &cli.root {
        Some(root) => root.clone(),
        None => default_root()?,
    };
    match &cli.command {
        Task::LintCompleteness => lint_completeness::run(&root, out),
        Task::AllowGate => allow_gate::run(&root, out),
        Task::ProfileEq => profile_eq::run(&root, out),
        Task::CancelSafety => cancel_safety::run(&root, out),
        Task::Catalog(CatalogTask::Fetch { version, models }) => {
            catalog_fetch::run(&root, version, models.as_deref(), out)
        }
        Task::Catalog(CatalogTask::Extract) => catalog_extract::run(&root, out),
        Task::Catalog(CatalogTask::Build { version }) => catalog_build::run(&root, version, out),
        Task::I18nGen => i18n::generate(&root, out),
        Task::I18nCheck { locales_dir } => i18n::check(&root, locales_dir.as_deref(), out),
        Task::AssetsCheck { assets_dir } => assets::run(&root, assets_dir.as_deref(), out),
        Task::GenMetricDocs => metric_docs::generate(&root, out),
        Task::GenToolDocs => tool_docs::generate(&root, out),
        Task::Seccomp(SeccompTask::Trace { binary, out: dir }) => {
            seccomp::trace(&root, binary.as_deref(), dir.as_deref(), out)
        }
        Task::Seccomp(SeccompTask::Gen { traces, check }) => {
            seccomp_gen::generate(&root, traces.as_deref(), *check, out)
        }
    }
}

/// The repository root: the parent of this package's manifest directory.
///
/// # Errors
///
/// Returns [`GateError::NoRoot`] when the manifest directory has no parent.
fn default_root() -> Result<PathBuf, GateError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or(GateError::NoRoot)
}
