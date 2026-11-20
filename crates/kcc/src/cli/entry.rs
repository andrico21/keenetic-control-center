//! Command dispatch: parses nothing, runs one command, returns the exit code.

use std::env;

use kcc_i18n::{keys, locale::Locale};

use super::{
    accounts, api_keys,
    args::{Cli, Command, LocalCommand, McpCommand},
    args_domains::DomainCommand,
    context::{Ctx, Globals},
    dom_jobs, domains,
    exit::{Exit, Failure, Outcome},
    fleet, migrate, notify,
    output::Out,
    persist, preset, rci, routers, tls,
};
use crate::{server, server_error};

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
        Command::Completions { shell } => tls::completions(shell),
        Command::Local(command) => local(command, globals, out).await,
        Command::Domain(command) => domain(command, globals, out).await,
    };
    match outcome {
        Ok(()) => 0,
        Err(failure) => {
            out.failure(&failure);
            failure.exit().code()
        }
    }
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
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: see `run`.
async fn local(command: LocalCommand, globals: Globals, out: Out) -> Outcome {
    match command {
        LocalCommand::Tls(sub) => tls::self_signed(out, sub),
        LocalCommand::Healthcheck => tls::healthcheck(&globals).await,
        LocalCommand::Router(sub) => routers::router(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Info => fleet::info(&Ctx::open(globals, out)?).await,
        LocalCommand::Show { words } => fleet::show(&Ctx::open(globals, out)?, &words).await,
        LocalCommand::Catalog(sub) => fleet::catalog(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Rci(sub) => rci::run(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Config(sub) => dom_jobs::config(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Backup(sub) => persist::backup(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Migrate(sub) => migrate::run(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Preset(sub) => preset::commands::run(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Copy(args) => preset::copy::run(&Ctx::open(globals, out)?, args).await,
        LocalCommand::User(sub) => accounts::user(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Apikey(sub) => api_keys::api_key(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Admin(sub) => accounts::admin(&Ctx::open(globals, out)?, sub).await,
        LocalCommand::Audit(sub) => api_keys::audit(&Ctx::open(globals, out)?, &sub),
        LocalCommand::Notify(sub) => notify::run(&Ctx::open(globals, out)?, sub).await,
    }
}

/// Runs one curated domain command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: see `run`.
async fn domain(command: DomainCommand, globals: Globals, out: Out) -> Outcome {
    domains::run(&Ctx::open(globals, out)?, command).await
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
