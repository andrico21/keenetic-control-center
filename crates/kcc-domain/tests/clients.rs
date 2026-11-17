//! Clients domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::time::Duration;

use kcc_app::{audit::verify_chain, workflow::WorkflowError};
use kcc_domain::clients;
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult};

#[tokio::test]
async fn denying_an_unregistered_client_registers_then_blocks_it() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mac = "02:00:00:00:10:02";
        let client = clients::read_client(fixture.context(), mac)
            .await?
            .ok_or("fixture client")?;
        assert_eq!(client.registered, Some(false));

        let operation = clients::plan_access(
            fixture.context(),
            &client,
            "blocked-device",
            clients::Access::Deny,
        )?;
        let mut changes = fixture.changes().await?;
        let result = clients::apply(&mut changes, fixture.context(), &operation).await?;

        assert!(result.unsaved);
        let blocked = clients::read_client(fixture.context(), mac)
            .await?
            .ok_or("registered client")?;
        assert_eq!(blocked.name.as_deref(), Some("blocked-device"));
        assert_eq!(blocked.registered, Some(true));
        assert_eq!(blocked.access.as_deref(), Some("deny"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn removing_a_client_uses_known_host_cascade() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mac = "02:00:00:00:10:aa";
        let registration = clients::plan_register(fixture.context(), mac.parse()?, "temporary")?;
        let mut changes = fixture.changes().await?;
        drop(clients::apply(&mut changes, fixture.context(), &registration).await?);

        let removal = clients::plan_remove(fixture.context(), mac)?;
        drop(clients::apply(&mut changes, fixture.context(), &removal).await?);

        assert!(
            clients::read_client(fixture.context(), mac)
                .await?
                .is_none()
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// C-23: the client read-back runs before the workflow writes its audit entry, so a failed
/// read-back leaves no `router.change_cli` entry claiming the change applied.
#[tokio::test]
async fn a_failed_client_read_back_is_not_audited_as_applied() -> TestResult {
    for firmware in PROFILES {
        let faults = FaultInjection::default().fail_read_matching("show/ip/hotspot", 1);
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        let mut client = clients::Client::default();
        client.mac = Some("02:00:00:00:10:03".to_owned());
        client.registered = Some(true);
        let operation = clients::plan_access(
            fixture.context(),
            &client,
            "phone-registered",
            clients::Access::Deny,
        )?;
        let mut changes = fixture.changes().await?;

        let result = clients::apply(&mut changes, fixture.context(), &operation).await;

        assert!(
            matches!(result, Err(WorkflowError::Rci(_))),
            "{firmware:?}: {result:?}"
        );
        assert_eq!(fixture.audit().flush(Duration::from_secs(60)).await, 0);
        let applied = verify_chain(&fixture.state_dir())?
            .into_iter()
            .filter(|entry| entry.action.starts_with("router.change_cli"))
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(applied, Vec::<String>::new(), "{firmware:?}");
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
