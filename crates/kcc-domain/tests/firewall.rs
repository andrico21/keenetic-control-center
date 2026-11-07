//! Firewall domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

extern crate alloc;

use alloc::sync::Arc;

use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    firewall::{
        change,
        descriptor::DESCRIPTOR,
        model::{Action, Protocol, Rule},
        read,
    },
};
use kcc_rci::version::FirmwareVersion;

use crate::support::{Fixture, TestResult};

#[tokio::test]
async fn access_list_rule_is_catalog_validated_and_visible_in_fresh_configuration() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let rule = Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", "198.51.100.20")
        .with_source_port(1024)
        .with_destination_port(443);
    let mut changes = fixture.changes().await?;

    drop(
        change::apply(
            &mut changes,
            fixture.context(),
            &change::plan_add_rule(fixture.context(), "WebAcl", &rule)?,
        )
        .await?,
    );

    let lists = read::access_lists(fixture.context()).await?;
    assert!(lists.get("WebAcl").is_some());
    assert!(lists.to_string().contains("198.51.100.20"));
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn upnp_redirects_are_read_from_the_router() -> TestResult {
    let fixture = Fixture::spawn().await?;

    let redirects = read::upnp_redirects(fixture.context()).await?;

    assert_eq!(redirects.len(), 1);
    let redirect = redirects.first().ok_or("missing fixture redirect")?;
    assert_eq!(redirect.external_port, Some(40_000));
    assert_eq!(redirect.internal_address.as_deref(), Some("192.0.2.40"));
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn ipv6_access_lists_are_not_offered_on_firmware_4_3_9() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let catalog =
        Catalog::for_firmware_and_model("4.3.9".parse::<FirmwareVersion>()?, Some("KN-1811"))?;
    let context = RouterCtx::new(Arc::clone(&fixture.context().client), catalog);

    let available = read::ipv6_available(&context);

    assert!(!available);
    assert!(
        !DESCRIPTOR
            .available_writes(&context.catalog)
            .any(|operation| operation.catalog_path == "ipv6 access-list")
    );
    fixture.shutdown().await?;
    Ok(())
}
