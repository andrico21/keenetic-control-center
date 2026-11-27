//! Command dispatch: parses nothing, runs one command, returns the exit code.

use core::pin::Pin;
use std::{env, io};

use kcc_i18n::{keys, locale::Locale};
use tracing_subscriber::EnvFilter;

use super::{
    accounts, api_keys,
    args::{Cli, Command, LocalCommand},
    args_domains::DomainCommand,
    args_mcp::McpCommand,
    context::{Ctx, Globals},
    dom_jobs, domains,
    exit::{Exit, Failure, Outcome},
    fleet, mcp, migrate, notify,
    output::Out,
    persist, preset, rci, routers, scheduled, tls,
};
use crate::{server, server_error};

/// One command's future, on the heap.
///
/// The dispatchers return it instead of awaiting their arms: an unoptimized build gives an
/// async fn's poll frame a slot for every arm's future at once, and that frame stays on
/// the stack under the whole command, which must fit Windows' 1 MiB main stack.
pub(super) type Boxed<'ctx> = Pin<Box<dyn Future<Output = Outcome> + Send + 'ctx>>;

/// Runs the parsed command and returns its process exit code.
///
/// Errors are reported on stderr in the output language (or as JSON with `--json`).
// NOT cancel-safe: commands may change routers and local state.
#[inline]
pub async fn run(cli: Cli) -> u8 {
    let out = match locale(cli.lang.as_deref()) {
        Ok(locale) => Out::new(cli.json, locale),
        Err(failure) => {
            Out::new(cli.json, locale(None).unwrap_or(Locale::En)).failure(&failure);
            return failure.exit().code();
        }
    };
    let globals = Globals::from_cli(&cli);
    let outcome = match cli.command {
        Command::Serve => return server_code(server::run_serve(cli.config).await, out),
        Command::Mcp(McpCommand::Stdio) => {
            return server_code(server::run_stdio(cli.config).await, out);
        }
        Command::Mcp(command) => {
            init_stderr_logging();
            mcp_command(command, globals, out).await
        }
        Command::Completions { shell } => tls::completions(shell),
        Command::Local(command) => {
            init_stderr_logging();
            local(command, globals, out).await
        }
        Command::Domain(command) => {
            init_stderr_logging();
            domain(command, globals, out).await
        }
    };
    match outcome {
        Ok(()) => 0,
        Err(failure) => {
            out.failure(&failure);
            failure.exit().code()
        }
    }
}

/// Installs the process's log subscriber on stderr when `RUST_LOG` is set and not empty.
///
/// Only the short-lived commands call it: `serve` and `mcp stdio` install their own
/// subscriber, which fails when one already exists. An existing subscriber is left alone.
fn init_stderr_logging() {
    if env::var_os("RUST_LOG").is_none_or(|filter| filter.is_empty()) {
        return;
    }
    drop(
        tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_ansi(false)
            .with_env_filter(EnvFilter::from_default_env())
            .try_init(),
    );
}

/// Reports a command-line parse failure and returns the process exit code.
///
/// Help and version go to stdout as clap prints them. A usage error goes to stderr: as the
/// failure envelope when `--json` is among `arguments`, else as clap prints it.
#[inline]
#[must_use]
pub fn report_parse_error(error: &clap::Error, arguments: &[String]) -> u8 {
    let code = u8::try_from(error.exit_code()).unwrap_or(Exit::Usage.code());
    let json = error.use_stderr()
        && arguments
            .iter()
            .take_while(|argument| *argument != "--")
            .any(|argument| argument == "--json");
    if json {
        let failure = Failure::text(Exit::Usage, &error.to_string().trim_end());
        Out::new(true, locale(None).unwrap_or(Locale::En)).failure(&failure);
        return Exit::Usage.code();
    }
    drop(error.print());
    code
}

/// Runs one command on the router profiles, the state directory or the server's files.
///
/// The returned future fails with the command's failure and its exit code.
// NOT cancel-safe: see `run`.
fn local(command: LocalCommand, globals: Globals, out: Out) -> Boxed<'static> {
    match command {
        LocalCommand::Tls(sub) => Box::pin(async move { tls::self_signed(out, sub) }),
        LocalCommand::Healthcheck => Box::pin(async move { tls::healthcheck(&globals).await }),
        LocalCommand::Router(sub) => {
            Box::pin(async move { routers::router(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Info => Box::pin(async move { fleet::info(&Ctx::open(globals, out)?).await }),
        LocalCommand::Show { words } => {
            Box::pin(async move { fleet::show(&Ctx::open(globals, out)?, &words).await })
        }
        LocalCommand::Catalog(sub) => {
            Box::pin(async move { fleet::catalog(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Rci(sub) => {
            Box::pin(async move { rci::run(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Config(sub) => {
            Box::pin(async move { dom_jobs::config(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Backup(sub) => {
            Box::pin(async move { persist::backup(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Migrate(sub) => {
            Box::pin(async move { migrate::run(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Preset(sub) => {
            Box::pin(async move { preset::commands::run(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Copy(args) => {
            Box::pin(async move { preset::copy::run(&Ctx::open(globals, out)?, args).await })
        }
        LocalCommand::User(sub) => {
            Box::pin(async move { accounts::user(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Apikey(sub) => {
            Box::pin(async move { api_keys::api_key(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Admin(sub) => {
            Box::pin(async move { accounts::admin(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Audit(sub) => {
            Box::pin(async move { api_keys::audit(&Ctx::open(globals, out)?, &sub) })
        }
        LocalCommand::Notify(sub) => {
            Box::pin(async move { notify::run(&Ctx::open(globals, out)?, sub).await })
        }
        LocalCommand::Scheduled(sub) => {
            Box::pin(async move { scheduled::run(&Ctx::open(globals, out)?, sub).await })
        }
    }
}

/// Runs one `kcc mcp` command other than `stdio`.
///
/// The returned future fails with the command's failure and its exit code.
// NOT cancel-safe: see `run`.
fn mcp_command(command: McpCommand, globals: Globals, out: Out) -> Boxed<'static> {
    Box::pin(async move { mcp::run(&Ctx::open(globals, out)?, command).await })
}

/// Runs one curated domain command.
///
/// The returned future fails with the command's failure and its exit code.
// NOT cancel-safe: see `run`.
fn domain(command: DomainCommand, globals: Globals, out: Out) -> Boxed<'static> {
    Box::pin(async move { domains::run(&Ctx::open(globals, out)?, command).await })
}

/// The output language: `--lang`, else `KCC_LANG`, `LC_ALL` or `LANG`, else English.
///
/// # Errors
///
/// Returns a usage failure for an unsupported `--lang`.
fn locale(flag: Option<&str>) -> Outcome<Locale> {
    if let Some(tag) = flag {
        return Locale::from_tag(tag).ok_or_else(|| {
            Failure::message(
                Exit::Usage,
                keys::CLI_LANG_UNSUPPORTED,
                &[("value", &format!("{tag:?}"))],
            )
        });
    }
    Ok(["KCC_LANG", "LC_ALL", "LANG"]
        .into_iter()
        .filter_map(|name| env::var(name).ok())
        .find_map(|value| {
            let tag = value.split(['_', '.', '-']).next().unwrap_or_default();
            Locale::from_tag(tag)
        })
        .unwrap_or(Locale::En))
}

/// Maps a server command's result to its exit code.
fn server_code(result: Result<server_error::Outcome, server_error::ServerError>, out: Out) -> u8 {
    match result {
        Ok(outcome) => outcome.code(),
        Err(error) => {
            out.failure(&Failure::from(error));
            Exit::Generic.code()
        }
    }
}
