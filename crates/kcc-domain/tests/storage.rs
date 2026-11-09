//! Storage domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::{
    DomainError,
    storage::{self, MaintenanceAction, MaintenanceRequest},
};

use crate::support::{Fixture, PROFILES, TestResult, administrator};

#[tokio::test]
async fn media_and_usb_inventory_decode_typed_fixtures() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let media = storage::read_media(fixture.context()).await?;
        let usb = storage::read_usb(fixture.context()).await?;
        assert_eq!(
            media.first().and_then(|item| item.id.as_deref()),
            Some("Media0")
        );
        assert_eq!(
            usb.first().and_then(|item| item.id.as_deref()),
            Some("Usb0")
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unconfirmed_format_is_refused_before_any_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_count();
        let role = administrator();
        let result = storage::plan_maintenance(
            fixture.context(),
            MaintenanceAction::Format,
            MaintenanceRequest::new("router", &role, "Media0", Some("ext4"), false),
        );
        assert!(matches!(result, Err(DomainError::ConfirmationRequired)));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}
