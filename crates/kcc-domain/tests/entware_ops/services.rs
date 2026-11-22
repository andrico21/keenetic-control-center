//! Service listing, status and actions with Entware's `check` read-back and rc.func's
//! exit codes.

use kcc_app::workflow::WorkflowError;
use kcc_domain::entware::ssh::{
    error::EntwareError,
    ops::{ActionExit, ServiceVerb},
};
use kcc_ssh::{error::SshError, grammar::ServiceName, parse::ServiceState};

use crate::{
    harness::param,
    rig::{Done, Op, Rig},
    support::TestResult,
};

/// Whether `outcome` is the read-back failure naming `name`.
fn verification_failed(outcome: &Result<Done, EntwareError>, name: &str) -> bool {
    let expected = format!("service {name}");
    matches!(
        outcome,
        Err(EntwareError::Workflow(WorkflowError::VerificationFailed { field })) if *field == expected
    )
}

/// Whether the fake's service `name` runs.
fn running(rig: &Rig, name: &str) -> TestResult<bool> {
    Ok(rig
        .harness()
        .ssh()?
        .service(name)
        .ok_or("no such service")?
        .is_running())
}

/// Todo 11: the service listing keeps the init script names; `status` renders `check`.
#[tokio::test]
async fn the_listing_and_status_are_parsed() -> TestResult {
    let rig = Rig::start().await?;
    let Done::Services(names) = rig.ok(Op::Services).await? else {
        return Err("not a service listing".into());
    };
    let listed: Vec<&str> = names.iter().map(ServiceName::as_str).collect();
    assert_eq!(
        listed,
        [
            "S50nginx",
            "S51dropbear",
            "S60idle",
            "S61lame",
            "S70broken",
            "S71stuck",
            "S80odd",
            "S81liar",
            "S82liar"
        ]
    );
    for (name, state) in [
        ("S51dropbear", ServiceState::Running),
        ("S50nginx", ServiceState::Stopped),
    ] {
        let Done::State(read) = rig.ok(Op::Status(name)).await? else {
            return Err("not a state".into());
        };
        assert_eq!(read, state, "{name}");
    }
    Ok(())
}

/// Todo 11: start, restart and stop are read back with `check` (exit 0 each), each in one
/// session with its listing.
#[tokio::test]
async fn start_restart_and_stop_read_the_state_back() -> TestResult {
    let rig = Rig::start().await?;
    for (verb, state) in [
        (ServiceVerb::Start, ServiceState::Running),
        (ServiceVerb::Restart, ServiceState::Running),
        (ServiceVerb::Stop, ServiceState::Stopped),
    ] {
        let (before, counters) = (rig.commands()?, rig.harness().counters()?);
        let outcome = rig.outcome(Op::Action("S50nginx", verb)).await?;
        assert_eq!(
            rig.logins_since(counters)?,
            (1, 1, 0),
            "{verb:?}: one session"
        );
        assert_eq!(outcome.service.as_str(), "S50nginx");
        assert_eq!(
            (outcome.state, outcome.exit),
            (state, ActionExit::Done),
            "{verb:?}"
        );
        assert_eq!(
            running(&rig, "S50nginx")?,
            state == ServiceState::Running,
            "{verb:?}"
        );
        assert_eq!(
            rig.commands()? - before,
            3,
            "{verb:?}: listing, action, check"
        );
    }
    let entries = rig.harness().audited("entware.ssh.service_stop")?;
    let entry = entries.first().ok_or("no stop entry")?;
    assert_eq!(
        (entry.outcome.as_str(), param(entry, "service")),
        ("success", "S50nginx".into())
    );
    Ok(())
}

/// Todo 11: stopping a stopped service (exit 1) is fine and reads `Stopped` back.
#[tokio::test]
async fn stop_of_a_stopped_service_is_ok() -> TestResult {
    let rig = Rig::start().await?;
    let outcome = rig
        .outcome(Op::Action("S50nginx", ServiceVerb::Stop))
        .await?;
    assert_eq!(
        (outcome.state, outcome.exit),
        (ServiceState::Stopped, ActionExit::AlreadyStopped)
    );
    Ok(())
}

/// Todo 11: start and restart of a disabled service (exit 8) are `ServiceDisabled` with
/// the state read back: a start leaves a running process running, a restart stopped it.
#[tokio::test]
async fn a_disabled_service_reports_service_disabled() -> TestResult {
    let rig = Rig::start().await?;
    for (name, verb, state) in [
        ("S60idle", ServiceVerb::Start, ServiceState::Stopped),
        ("S61lame", ServiceVerb::Start, ServiceState::Running),
        ("S61lame", ServiceVerb::Restart, ServiceState::Stopped),
    ] {
        let outcome = rig.run(Op::Action(name, verb)).await?;
        assert!(
            matches!(
                &outcome,
                Err(EntwareError::ServiceDisabled { service, state: read })
                    if service == name && *read == state
            ),
            "{name} {verb:?}: {outcome:?}"
        );
    }
    assert!(!running(&rig, "S61lame")?);
    let entries = rig.harness().audited("entware.ssh.service_restart")?;
    let entry = entries.first().ok_or("no restart entry")?;
    assert_eq!(
        (entry.outcome.as_str(), param(entry, "reason")),
        ("refused", "service_disabled".into())
    );
    Ok(())
}

/// Todo 11: exit 255 of start, restart and stop is a failure by itself.
#[tokio::test]
async fn exit_255_fails() -> TestResult {
    let rig = Rig::start().await?;
    for (name, verb) in [
        ("S70broken", ServiceVerb::Start),
        ("S70broken", ServiceVerb::Restart),
        ("S71stuck", ServiceVerb::Stop),
    ] {
        let outcome = rig.run(Op::Action(name, verb)).await?;
        assert!(
            matches!(outcome, Err(EntwareError::Ssh(SshError::ServiceFailed))),
            "{name} {verb:?}: {outcome:?}"
        );
    }
    Ok(())
}

/// Todo 11: any other exit status is not an error by itself.
///
/// The `check` read-back decides: an unexpected status with the right state succeeds and
/// a success status with the wrong state fails, naming the service.
#[tokio::test]
async fn the_check_read_back_decides_other_statuses() -> TestResult {
    let rig = Rig::start().await?;
    let odd = rig
        .outcome(Op::Action("S80odd", ServiceVerb::Start))
        .await?;
    assert_eq!(
        (odd.state, odd.exit),
        (ServiceState::Running, ActionExit::Other(3))
    );
    for (name, verb) in [
        ("S81liar", ServiceVerb::Start),
        ("S81liar", ServiceVerb::Restart),
        ("S82liar", ServiceVerb::Stop),
    ] {
        let outcome = rig.run(Op::Action(name, verb)).await?;
        assert!(
            verification_failed(&outcome, name),
            "{name} {verb:?}: {outcome:?}"
        );
    }
    Ok(())
}

/// Todo 11: an action or status of a service missing from the listing is refused after
/// that one listing, with no action and no `check`.
#[tokio::test]
async fn an_unknown_service_is_refused_after_the_listing() -> TestResult {
    let rig = Rig::start().await?;
    for op in [
        Op::Action("S99none", ServiceVerb::Start),
        Op::Action("S99none", ServiceVerb::Stop),
        Op::Status("S99none"),
    ] {
        let before = rig.commands()?;
        let outcome = rig.run(op).await?;
        assert!(
            matches!(&outcome, Err(EntwareError::UnknownService { service }) if service == "S99none"),
            "{op:?}: {outcome:?}"
        );
        assert_eq!(rig.commands()? - before, 1, "{op:?}: only the listing ran");
    }
    Ok(())
}
