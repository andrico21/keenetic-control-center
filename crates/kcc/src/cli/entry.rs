//! Command dispatch: parses nothing, runs one command, returns the exit code.

use std::env;

use kcc_i18n::locale::Locale;

use super::{
    accounts, api_keys,
    args::{Cli, Command, McpCommand},
    context::{Ctx, Globals},
    domains,
    exit::{Exit, Failure, Outcome},
    fleet, migrate,
    output::Out,
    persist, preset, rci, routers, tls,
};
use crate::server;

/// Runs the parsed command and returns its process exit code.
///
/// Errors are reported on stderr in the output language (or as JSON with `--json`).
// NOT cancel-safe: commands may change routers and local state.
#[inline]
pub async fn run(cli: Cli) -> u8 {
    let out = match locale(cli.lang.as_deref()) {
        Ok(locale) => Out::new(cli.json, locale),
        Err(failure) => {
            Out::new(cli.json, Locale::En).failure(&failure);
            return failure.exit().code();
        }
    };
    let globals = Globals::from_cli(&cli);
    match cli.command {
        Command::Serve => return server_code(server::run_serve(cli.config).await, out),
        Command::Mcp(McpCommand::Stdio) => {
            return server_code(server::run_stdio(cli.config).await, out);
        }
        Command::Router(_)
        | Command::Info
        | Command::Show { words: _ }
        | Command::Rci(_)
        | Command::Catalog(_)
        | Command::Config(_)
        | Command::Backup(_)
        | Command::Migrate(_)
        | Command::Preset(_)
        | Command::Copy(_)
        | Command::User(_)
        | Command::Apikey(_)
        | Command::Admin(_)
        | Command::Audit(_)
        | Command::Healthcheck
        | Command::Tls(_)
        | Command::Completions { shell: _ }
        | Command::Domain(_) => {}
    }
    match dispatch(cli.command, globals, out).await {
        Ok(()) => 0,
        Err(failure) => {
            out.failure(&failure);
            failure.exit().code()
        }
    }
}

/// Runs one command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: see `run`.
async fn dispatch(command: Command, globals: Globals, out: Out) -> Outcome {
    match command {
        Command::Completions { shell } => tls::completions(shell),
        Command::Tls(sub) => tls::self_signed(out, sub),
        Command::Healthcheck => tls::healthcheck(&globals).await,
        Command::Serve | Command::Mcp(_) => Ok(()),
        Command::Router(sub) => routers::router(&Ctx::open(globals, out)?, sub).await,
        Command::Info => fleet::info(&Ctx::open(globals, out)?).await,
        Command::Show { words } => fleet::show(&Ctx::open(globals, out)?, &words).await,
        Command::Catalog(sub) => fleet::catalog(&Ctx::open(globals, out)?, sub).await,
        Command::Rci(sub) => rci::run(&Ctx::open(globals, out)?, sub).await,
        Command::Config(sub) => persist::config(&Ctx::open(globals, out)?, sub).await,
        Command::Backup(sub) => persist::backup(&Ctx::open(globals, out)?, sub).await,
        Command::Migrate(sub) => migrate::run(&Ctx::open(globals, out)?, sub).await,
        Command::Preset(sub) => preset::commands::run(&Ctx::open(globals, out)?, sub).await,
        Command::Copy(args) => preset::copy::run(&Ctx::open(globals, out)?, args).await,
        Command::User(sub) => accounts::user(&Ctx::open(globals, out)?, sub).await,
        Command::Apikey(sub) => api_keys::api_key(&Ctx::open(globals, out)?, sub).await,
        Command::Admin(sub) => accounts::admin(&Ctx::open(globals, out)?, sub).await,
        Command::Audit(sub) => api_keys::audit(&Ctx::open(globals, out)?, &sub),
        Command::Domain(sub) => domains::run(&Ctx::open(globals, out)?, sub).await,
    }
}

/// The output language: `--lang`, else `KCC_LANG`, `LC_ALL` or `LANG`, else English.
///
/// # Errors
///
/// Returns a usage failure for an unsupported `--lang`.
fn locale(flag: Option<&str>) -> Outcome<Locale> {
    if let Some(tag) = flag {
        return Locale::from_tag(tag).ok_or_else(|| {
            Failure::text(
                Exit::Usage,
                &format!("unsupported --lang {tag:?}; use en, ru, uk, de, be or kk"),
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
fn server_code(result: Result<server::Outcome, server::ServerError>, out: Out) -> u8 {
    match result {
        Ok(outcome) => outcome.code(),
        Err(error) => {
            out.failure(&Failure::text(Exit::Generic, &error));
            Exit::Generic.code()
        }
    }
}
