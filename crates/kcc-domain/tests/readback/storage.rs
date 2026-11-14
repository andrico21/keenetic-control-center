//! Storage maintenance never claims verified state; eject is the documented exclusion.

use kcc_domain::{
    DomainError,
    storage::{self, MaintenanceAction, MaintenanceRequest},
    verification,
};
use kcc_testkit::FaultInjection;

use crate::support::{Fixture, PROFILES, TestResult, administrator};

/// Unsupported partition commands fail before dispatch, even with no-op acknowledgements.
#[tokio::test]
async fn unavailable_partition_writes_are_refused_without_dispatch() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn_with_faults(
            firmware,
            FaultInjection::default().silent_noop_path("parse"),
        )
        .await?;
        let role = administrator();
        let before = fixture.handle().request_count();
        for action in [MaintenanceAction::Check, MaintenanceAction::Format] {
            let result = storage::plan_maintenance(
                fixture.context(),
                action,
                MaintenanceRequest::new("router", &role, "Media0", Some("ext4"), true),
            );
            assert!(
                matches!(result, Err(DomainError::Validation { issues: _ })),
                "unavailable maintenance must not become an unverified write: {result:?}"
            );
        }
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Eject is explicitly exempt because it can remove its own readable device surface.
#[tokio::test]
async fn eject_requires_the_documented_action_exclusion() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let plan = storage::plan_eject(
            fixture.context(),
            "router",
            &administrator(),
            "Media0",
            true,
        )?;
        verification::require(&storage::change_request(&plan)?)?;
        fixture.shutdown().await?;
    }
    Ok(())
}
