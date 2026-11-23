//! `kcc entware services`: the init scripts, their state, the actions read back with
//! `check`, and the router log of a service's process.

use kcc_domain::entware::{
    service_log::service_log,
    ssh::ops::{self, ActionExit, ServiceVerb},
};
use kcc_i18n::keys;
use kcc_ssh::{grammar::ServiceName, parse::ServiceState};
use serde_json::{Value, json};

use super::{
    args_dom_entware_ssh::EntwareServicesCommand,
    context::Ctx,
    dom_entware_ssh_gate::{clean, invalid_name, open, state_key, state_name},
    entry::Boxed,
    exit::Outcome,
    output::Out,
};

/// Runs an `entware services` command.
///
/// The returned future fails with the command's failure and its exit code; see [`Boxed`]
/// for why it is boxed.
// NOT cancel-safe: actions may run on the router after cancellation.
pub(crate) fn services(ctx: &Ctx, command: EntwareServicesCommand) -> Boxed<'_> {
    match command {
        EntwareServicesCommand::List => Box::pin(list(ctx)),
        EntwareServicesCommand::Status { name } => Box::pin(status(ctx, name)),
        EntwareServicesCommand::Start { name } => Box::pin(action(ctx, name, ServiceVerb::Start)),
        EntwareServicesCommand::Stop { name } => Box::pin(action(ctx, name, ServiceVerb::Stop)),
        EntwareServicesCommand::Restart { name } => {
            Box::pin(action(ctx, name, ServiceVerb::Restart))
        }
        EntwareServicesCommand::Log { name, lines } => Box::pin(log(ctx, name, lines)),
    }
}

/// The service `name`, parsed before anything else.
///
/// # Errors
///
/// Returns the validation failure (exit 4); nothing is sent.
fn parse(name: &str) -> Outcome<ServiceName> {
    ServiceName::parse(name).map_err(|_invalid| invalid_name())
}

/// Prints the init scripts.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router read may sign in first.
async fn list(ctx: &Ctx) -> Outcome {
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    let names = opened
        .read(
            out,
            ops::services_list(&opened.ssh(), target.router(), &opened.caller()),
        )
        .await?
        .iter()
        .map(|service| clean(service.as_str()))
        .collect::<Vec<_>>();
    let human = if names.is_empty() {
        out.tr(keys::CLI_ENTWARE_SERVICES_NONE, &[])
    } else {
        names.join("\n")
    };
    out.emit(&json!({ "services": names }), &human)
}

/// Prints whether the service `name` runs.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router read may sign in first.
async fn status(ctx: &Ctx, name: String) -> Outcome {
    let service = parse(&name)?;
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    let (ssh, caller) = (opened.ssh(), opened.caller());
    let read = ops::service_status(&ssh, target.router(), &caller, service);
    let state = opened.read(out, read).await?;
    emit_state(
        out,
        (&name, state),
        &json!({ "service": clean(&name), "state": state_name(state) }),
    )
}

/// Runs `verb` on the service `name` and prints the state read back.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router may finish the action after cancellation.
async fn action(ctx: &Ctx, name: String, verb: ServiceVerb) -> Outcome {
    let service = parse(&name)?;
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    let outcome = ops::service_action(
        &opened.ssh(),
        target.router(),
        &opened.caller(),
        service,
        verb,
    )
    .await
    .map_err(|error| opened.failure(out, error))?;
    let exit = match outcome.exit {
        ActionExit::Done => json!("done"),
        ActionExit::AlreadyStopped => json!("already_stopped"),
        ActionExit::Other(code) => json!({ "other": code }),
        _ => Value::Null,
    };
    let document = json!({
        "service": clean(outcome.service.as_str()),
        "state": state_name(outcome.state),
        "exit": exit,
    });
    emit_state(out, (&name, outcome.state), &document)
}

/// Prints `document`, or the line of the service `name` in `state`.
///
/// # Errors
///
/// Returns output failures.
fn emit_state(out: Out, (name, state): (&str, ServiceState), document: &Value) -> Outcome {
    let word = out.tr(state_key(state), &[]);
    out.emit(
        document,
        &out.tr(
            keys::CLI_ENTWARE_SERVICE_STATE,
            &[("name", &clean(name)), ("value", &word)],
        ),
    )
}

/// Prints the newest `lines` router log records of the service `name`'s process.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the log read may sign in first.
async fn log(ctx: &Ctx, name: String, lines: u32) -> Outcome {
    let service = parse(&name)?;
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    let records = service_log(target.router(), &opened.caller(), service, lines)
        .await
        .map_err(|error| opened.failure(out, error))?;
    let values = records
        .iter()
        .map(|record| {
            json!({
                "id": record.id,
                "time": record.ts.to_string(),
                "level": clean(&record.level),
                "process": record.process.as_deref().map(clean),
                "message": clean(&record.message),
            })
        })
        .collect::<Vec<_>>();
    let human = if records.is_empty() {
        out.tr(
            keys::CLI_ENTWARE_SERVICE_LOG_EMPTY,
            &[("name", &clean(&name))],
        )
    } else {
        records
            .iter()
            .map(|record| {
                format!(
                    "{} {} {}",
                    record.ts,
                    clean(&record.level),
                    clean(&record.message)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    out.emit(
        &json!({ "service": clean(&name), "records": values }),
        &human,
    )
}
