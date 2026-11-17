//! Router log commands, and the parsing of router object names.

use kcc_app::permissions::Permission;
use kcc_domain::logging;
use kcc_i18n::keys;
use kcc_rci::ObjectName;

use super::{
    args_domains_wire::LogCommand,
    context::Ctx,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `log` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn log(ctx: &Ctx, command: LogCommand) -> Outcome {
    let permission = match command {
        LogCommand::Read { lines: _ } => Permission::Read,
        LogCommand::Clear => Permission::Destructive,
        LogCommand::Server {
            address: _,
            port: _,
            state: _,
        }
        | LogCommand::Reduction { state: _ }
        | LogCommand::Suppress { ident: _, state: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        LogCommand::Read { lines } => {
            return session.show(&logging::read_log(router, lines).await?);
        }
        LogCommand::Server {
            address,
            port,
            state,
        } => logging::plan_server(router, &address, port, state.enabled())?,
        LogCommand::Reduction { state } => logging::plan_reduction(router, state.enabled())?,
        LogCommand::Suppress { ident, state } => {
            logging::plan_suppress(router, &ident, state.enabled())?
        }
        LogCommand::Clear => {
            let target = session.target();
            logging::plan_clear(router, target.id(), target.role(), true)?
        }
    };
    session
        .cli(&operation, logging::change_request(&operation)?)
        .await
}

/// Parses a router object name, e.g. `Bridge0` or `WifiMaster0/AccessPoint0`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
pub(crate) fn object(name: &str) -> Outcome<ObjectName> {
    name.parse().map_err(|_error| {
        Failure::message(Exit::Validation, keys::CLI_NOT_FOUND, &[("name", name)])
    })
}
