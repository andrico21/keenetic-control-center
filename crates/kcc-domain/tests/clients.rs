//! Clients domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::clients;

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
