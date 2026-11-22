//! Todo 11: `service_log` keeps the records of the service's process, newest last, at
//! most `max_lines`, masks secrets unless the role may reveal them, and needs
//! `Destructive`.

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::{Permission, Role},
};
use kcc_domain::entware::{
    service_log::service_log,
    ssh::{Caller, error::EntwareError},
};
use kcc_ssh::grammar::ServiceName;
use kcc_testkit::{entware_install::record, model::Firmware};

use crate::support::{Fixture, PROFILES, TestResult, administrator};

/// The router id of the fixture profile.
const ROUTER: &str = "router";

/// A role with every permission but `without`.
fn all_but(without: Permission) -> Role {
    Role::new(
        "limited".to_owned(),
        Permission::ALL
            .into_iter()
            .filter(|permission| *permission != without),
        vec!["*".to_owned()],
    )
}

/// A secret-shaped payload built at run time.
fn blob() -> String {
    "QUJD".repeat(6)
}

/// Seeds records of dropbear (one with a secret), nginx and a component line.
fn seed(fixture: &Fixture) {
    let handle = fixture.handle();
    handle.insert_log(10, record("I", "dropbear[123]: Running in background"));
    handle.insert_log(11, record("I", "nginx[7]: worker started"));
    handle.insert_log(
        12,
        record(
            "W",
            &format!("dropbear[123]: authentication wpa-psk ns3 {}", blob()),
        ),
    );
    handle.insert_log(13, record("I", "Opkg::Manager: dropbear checked"));
    handle.insert_log(14, record("I", "dropbear[124]: Child connection"));
}

/// The messages `role` reads from S51dropbear's log, at most `max_lines`.
// NOT cancel-safe: the log read may sign in first.
async fn messages(
    fixture: &Fixture,
    role: &Role,
    max_lines: u32,
) -> TestResult<Result<Vec<(u64, String)>, EntwareError>> {
    let actor = Actor::new(ActorKind::Web, "alice".to_owned());
    let caller = Caller::new(ROUTER, &actor, role);
    let service = ServiceName::parse("S51dropbear")?;
    Ok(service_log(fixture.context(), &caller, service, max_lines)
        .await
        .map(|records| {
            records
                .into_iter()
                .map(|record| (record.id, record.message))
                .collect()
        }))
}

/// Todo 11: only the service's process records are kept, in id order; a secret is
/// masked for a role without `RevealSecrets` and shown to one with it.
#[tokio::test]
async fn the_log_is_filtered_and_masked() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        seed(&fixture);
        let masked = messages(&fixture, &all_but(Permission::RevealSecrets), 50).await??;
        let ids: Vec<u64> = masked.iter().map(|(id, _message)| *id).collect();
        assert_eq!(ids, [10, 12, 14], "{firmware:?}");
        let secret = masked.get(1).ok_or("no secret line")?;
        assert!(!secret.1.contains(&blob()), "{firmware:?}: {secret:?}");
        assert!(secret.1.contains("<redacted>"), "{firmware:?}: {secret:?}");
        let revealed = messages(&fixture, &administrator(), 50).await??;
        let shown = revealed.get(1).ok_or("no secret line")?;
        assert!(shown.1.contains(&blob()), "{firmware:?}: {shown:?}");
    }
    Ok(())
}

/// Todo 11: `max_lines` keeps the newest records of the service.
#[tokio::test]
async fn max_lines_keeps_the_newest() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    seed(&fixture);
    let newest = messages(&fixture, &administrator(), 2).await??;
    let ids: Vec<u64> = newest.iter().map(|(id, _message)| *id).collect();
    assert_eq!(ids, [12, 14]);
    Ok(())
}

/// Todo 11: a role without `Destructive` is refused before any router request.
#[tokio::test]
async fn the_log_needs_destructive() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    seed(&fixture);
    let requests = fixture.handle().request_count();
    let outcome = messages(&fixture, &all_but(Permission::Destructive), 50).await?;
    assert!(
        matches!(outcome, Err(EntwareError::PermissionDenied)),
        "{outcome:?}"
    );
    assert_eq!(fixture.handle().request_count(), requests);
    Ok(())
}
