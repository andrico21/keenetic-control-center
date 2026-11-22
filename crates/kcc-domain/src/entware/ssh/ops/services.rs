//! The service listing, `check` and the actions with their `check` read-back.

use kcc_app::workflow::WorkflowError;
use kcc_ssh::{
    command::EntwareCommand,
    error::SshError,
    grammar::{ServiceAction, ServiceName},
    parse::{self, ServiceState},
    session::Session,
};

use super::{ActionExit, Run, ServiceOutcome, ServiceVerb, session};
use crate::{RouterCtx, entware::ssh::error::EntwareError};

/// The init scripts.
///
/// # Errors
/// As [`super::services_list`].
// NOT cancel-safe: the chroot read may sign in first.
pub(super) async fn listing(
    run: &mut Run<'_>,
    router: &RouterCtx,
) -> Result<Vec<ServiceName>, EntwareError> {
    run.read()?;
    let session = session::open(run, router).await?;
    let output = run.exec(&session, &EntwareCommand::ListServices).await?;
    drop(session);
    Ok(parse::services(&output)?)
}

/// The listed `service`'s `check`.
///
/// # Errors
/// As [`super::service_status`].
// NOT cancel-safe: the chroot read may sign in first.
pub(super) async fn status(
    run: &mut Run<'_>,
    router: &RouterCtx,
    service: ServiceName,
) -> Result<ServiceState, EntwareError> {
    run.read()?;
    run.facts.service = Some(service.as_str().to_owned());
    let session = session::open(run, router).await?;
    listed(run, &session, &service).await?;
    check(run, &session, &service).await
}

/// `verb` on the listed `service` under the lease, read back with `check`.
///
/// # Errors
/// As [`super::service_action`].
// NOT cancel-safe: dropped while the action runs, the service may still change state.
pub(super) async fn action(
    run: &mut Run<'_>,
    router: &RouterCtx,
    service: ServiceName,
    verb: ServiceVerb,
) -> Result<ServiceOutcome, EntwareError> {
    let _lease = run.write()?;
    run.facts.service = Some(service.as_str().to_owned());
    let session = session::open(run, router).await?;
    listed(run, &session, &service).await?;
    let command = EntwareCommand::Service(service.clone(), verb.action());
    let reported = match (verb, run.exec(&session, &command).await?.exit_status()) {
        (_, 8) => None,
        (_, 255) => return Err(SshError::ServiceFailed.into()),
        (_, 0) => Some(ActionExit::Done),
        (ServiceVerb::Stop, 1) => Some(ActionExit::AlreadyStopped),
        (_, code) => Some(ActionExit::Other(code)),
    };
    let state = check(run, &session, &service).await?;
    drop(session);
    let Some(exit) = reported else {
        return Err(EntwareError::ServiceDisabled {
            service: service.as_str().to_owned(),
            state,
        });
    };
    let expected = match verb {
        ServiceVerb::Start | ServiceVerb::Restart => ServiceState::Running,
        ServiceVerb::Stop => ServiceState::Stopped,
    };
    if state != expected {
        return Err(WorkflowError::VerificationFailed {
            field: format!("service {}", service.as_str()),
        }
        .into());
    }
    Ok(ServiceOutcome {
        service,
        state,
        exit,
    })
}

/// Refuses a `service` the listing of `session` lacks.
///
/// # Errors
/// [`EntwareError::UnknownService`], or the listing's failure.
// NOT cancel-safe: a dropped read leaves only a read-only command behind.
async fn listed(
    run: &mut Run<'_>,
    session: &Session,
    service: &ServiceName,
) -> Result<(), EntwareError> {
    let output = run.exec(session, &EntwareCommand::ListServices).await?;
    if parse::services(&output)?.contains(service) {
        return Ok(());
    }
    Err(EntwareError::UnknownService {
        service: service.as_str().to_owned(),
    })
}

/// `service`'s state as rc.func's `check` reports it.
///
/// # Errors
/// The command's failure or an output that is neither `alive.` nor `dead.`.
// NOT cancel-safe: a dropped read leaves only a read-only command behind.
async fn check(
    run: &mut Run<'_>,
    session: &Session,
    service: &ServiceName,
) -> Result<ServiceState, EntwareError> {
    let command = EntwareCommand::Service(service.clone(), ServiceAction::Check);
    Ok(parse::service_state(&run.exec(session, &command).await?)?)
}
