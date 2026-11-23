//! Runs the `entware-ssh` tools: the shared gates of every operation, the reads with
//! their bound and cleaned values, and the mutations as write jobs.

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_domain::{
    RouterCtx,
    entware::{
        service_log::service_log,
        ssh::{
            Caller, SshServices,
            error::EntwareError,
            ops::{
                self,
                job::{self, Mutation, Request},
                names,
            },
        },
    },
};
use serde_json::{Value, json};
use tokio::time::timeout;

use super::{common::open_as, jobs::started};
use crate::{
    KccMcp, McpFailure,
    support::{
        audit::Success,
        errors::{map_domain, map_workflow},
        plain::{bounded, plain},
        route::Progress,
    },
};

/// Characters a version or a log level keeps in a result.
const VERSION_CHARS: usize = 128;

/// Characters a log message keeps in a result.
const MESSAGE_CHARS: usize = 1024;

/// A checked operation.
pub(crate) enum Call {
    /// A read, answered directly.
    Read(Read),
    /// A mutation, run as a write job.
    Mutation(Mutation),
}

/// A checked read.
pub(crate) enum Read {
    /// The installed packages, or those with an upgrade, from `offset`.
    Packages {
        /// Only the upgradable packages, with the offered version.
        upgradable: bool,
        /// Items skipped.
        offset: usize,
    },
    /// The init scripts from `offset`.
    Services {
        /// Items skipped.
        offset: usize,
    },
    /// The state of a service whose name passed the grammar.
    Status(String),
    /// The newest `lines` log records of a service whose name passed the grammar, from
    /// `offset`.
    Log {
        /// The init script.
        service: String,
        /// Records read.
        lines: u32,
        /// Items skipped.
        offset: usize,
    },
}

/// One checked call: its tool, router, confirmation and operation.
pub(crate) struct Target {
    /// The tool, the audit action of a started job.
    tool: &'static str,
    /// Router profile id.
    host: String,
    /// The call's `confirm`.
    confirm: bool,
    /// The operation.
    call: Call,
}

impl Target {
    /// `call` of `tool` on the router and with the confirmation of `request`.
    pub(crate) fn new(tool: &'static str, request: (String, bool), call: Call) -> Self {
        let (host, confirm) = request;
        Self {
            tool,
            host,
            confirm,
            call,
        }
    }
}

/// Runs the target's operation after the gates of every operation: `Destructive` on the
/// router, `allow_destructive` and `confirm`, then the router context.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: a mutation job may be started, and its audit entry queued, before the
// future is dropped; a dropped read may leave its audit entry unwritten.
pub(crate) async fn run(
    server: &KccMcp,
    target: Target,
    progress: Option<Progress>,
) -> Result<Value, McpFailure> {
    let (services, limit) = server.entware_ssh.clone().ok_or_else(|| {
        tracing::error!("MCP Entware SSH services are not attached");
        McpFailure::Internal
    })?;
    let (identity, router, ctx) = open_as(
        server,
        (Permission::Destructive, Risk::Destructive),
        (target.host, target.confirm),
    )
    .await?;
    let actor = Actor::new(ActorKind::Mcp, identity.name.clone());
    match target.call {
        Call::Read(read) => {
            let caller = Caller::new(router.as_str(), &actor, &identity.role);
            timeout(limit, answer(&services, &ctx, &caller, read))
                .await
                .map_err(|_elapsed| {
                    tracing::warn!(router = router.as_str(), "MCP Entware read hit its bound");
                    McpFailure::Conflict
                })?
        }
        Call::Mutation(mutation) => {
            let request = Request::new(ctx, router.as_str().to_owned(), actor, identity.role);
            let events = server.jobs.subscribe();
            let id = job::start(&server.jobs, services, request, mutation)
                .await
                .map_err(map_entware)?;
            let kind = server
                .jobs
                .get(&id)
                .ok()
                .map_or_default(|record| record.kind);
            let done = Success::new(target.tool)
                .on_router(router.as_str())
                .with_target(kind)
                .with_params(json!({ "id": id }));
            let result = started(id, events, progress).await;
            Ok(done.record(server, result).await)
        }
    }
}

/// Answers one read with parsed values whose text is cleaned of control characters.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: the operation's audit entry may be appended after cancellation.
async fn answer(
    services: &SshServices,
    ctx: &RouterCtx,
    caller: &Caller<'_>,
    read: Read,
) -> Result<Value, McpFailure> {
    let checked =
        |name: &str| names::service(name).map_err(|_grammar| McpFailure::InvalidArguments);
    Ok(match read {
        Read::Packages { upgradable, offset } => {
            let listed = if upgradable {
                ops::packages_upgradable(services, ctx, caller).await
            } else {
                ops::packages_list(services, ctx, caller).await
            }
            .map_err(map_entware)?;
            let packages = listed.into_iter().skip(offset).map(|package| {
                let (version, version_cut) = bounded(&package.version, VERSION_CHARS);
                let offered = package
                    .new_version
                    .as_deref()
                    .map(|new| bounded(new, VERSION_CHARS));
                let cut = version_cut || offered.as_ref().is_some_and(|&(_, new_cut)| new_cut);
                let mut item = json!({
                    "name": plain(package.name.as_str()),
                    "version": version,
                });
                if let (true, Value::Object(members)) = (upgradable, &mut item) {
                    let new_version = offered.map(|(kept, _)| kept);
                    drop(members.insert("new_version".to_owned(), json!(new_version)));
                }
                marked(item, cut)
            });
            let op = if upgradable { "upgradable" } else { "list" };
            json!({ "op": op, "packages": packages.collect::<Vec<_>>() })
        }
        Read::Services { offset } => {
            let listed = ops::services_list(services, ctx, caller)
                .await
                .map_err(map_entware)?;
            let named = listed.iter().skip(offset);
            let items = named.map(|name| json!({ "name": plain(name.as_str()) }));
            json!({ "op": "list", "services": items.collect::<Vec<_>>() })
        }
        Read::Status(service) => {
            let state = ops::service_status(services, ctx, caller, checked(&service)?)
                .await
                .map_err(map_entware)?;
            json!({ "op": "status", "service": service, "state": names::state_word(state) })
        }
        Read::Log {
            service,
            lines,
            offset,
        } => {
            let records = service_log(ctx, caller, checked(&service)?, lines)
                .await
                .map_err(map_entware)?;
            let items = records.into_iter().skip(offset).map(|record| {
                let (level, level_cut) = bounded(&record.level, VERSION_CHARS);
                let (message, message_cut) = bounded(&record.message, MESSAGE_CHARS);
                let item = json!({
                    "id": record.id,
                    "time": record.ts.to_string(),
                    "level": level,
                    "message": message,
                });
                marked(item, level_cut || message_cut)
            });
            json!({ "op": "log", "service": service, "records": items.collect::<Vec<_>>() })
        }
    })
}

/// `item` with `"cut": true` when one of its strings was cut to its bound.
fn marked(mut item: Value, cut: bool) -> Value {
    if let (true, Value::Object(members)) = (cut, &mut item) {
        drop(members.insert("cut".to_owned(), Value::Bool(true)));
    }
    item
}

/// Maps an Entware SSH failure; the error text carries no output, so it may be logged.
fn map_entware(error: EntwareError) -> McpFailure {
    tracing::warn!(%error, "MCP Entware SSH operation failed");
    match error {
        EntwareError::PermissionDenied | EntwareError::McpRefused => McpFailure::Forbidden,
        EntwareError::PackageNotInstalled { package: _ }
        | EntwareError::UnknownService { service: _ } => McpFailure::InvalidArguments,
        EntwareError::ChrootEnabled
        | EntwareError::RouterHostChanged
        | EntwareError::NotEnrolled
        | EntwareError::RepinRequired
        | EntwareError::HostKeyUnchanged
        | EntwareError::SshDisabled
        | EntwareError::ServiceDisabled {
            service: _,
            state: _,
        } => McpFailure::Conflict,
        EntwareError::Workflow(workflow) => map_workflow(workflow),
        EntwareError::Domain(domain) | EntwareError::RevokeUnreachable(domain) => {
            map_domain(domain)
        }
        EntwareError::Ssh(_) | EntwareError::RevokeFailed(_) => McpFailure::RouterUnreachable,
        EntwareError::Job(_) => McpFailure::JobUnavailable,
        // An error this version does not know is internal.
        EntwareError::State(_) | EntwareError::Audit(_) | _ => McpFailure::Internal,
    }
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test code fails by panicking")]
mod tests {
    use kcc_app::workflow::WorkflowError;
    use kcc_domain::entware::ssh::error::EntwareError;

    use super::map_entware;
    use crate::McpFailure;

    /// Todo 17: the enrolment and state refusals are conflicts, a busy router write lease
    /// is a conflict, absent packages and services are invalid arguments.
    #[test]
    fn entware_failures_keep_their_codes() {
        for (error, expected) in [
            (EntwareError::PermissionDenied, McpFailure::Forbidden),
            (EntwareError::NotEnrolled, McpFailure::Conflict),
            (EntwareError::ChrootEnabled, McpFailure::Conflict),
            (EntwareError::SshDisabled, McpFailure::Conflict),
            (
                EntwareError::Workflow(WorkflowError::RouterBusy {
                    actor: "alice".to_owned(),
                }),
                McpFailure::Conflict,
            ),
            (
                EntwareError::PackageNotInstalled {
                    package: "htop".to_owned(),
                },
                McpFailure::InvalidArguments,
            ),
            (
                EntwareError::UnknownService {
                    service: "S50x".to_owned(),
                },
                McpFailure::InvalidArguments,
            ),
        ] {
            assert_eq!(map_entware(error), expected);
        }
    }
}
