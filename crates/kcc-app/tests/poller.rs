//! Poller integration tests.
#![expect(
    clippy::absolute_paths,
    clippy::default_numeric_fallback,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration-test crate structure and bounded fixture loop"
)]

use core::{error::Error, time::Duration};
use std::sync::Arc;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    poller::{PollIntervals, Poller},
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;

#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions and fixtures define the contract"
)]
#[tokio::test]
async fn ten_subscribers_share_one_light_poll_round() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle) = FakeRouter::spawn().await?;
    let password = directory.path().join("password");
    std::fs::write(&password, DEFAULT_PASSWORD)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let registry = Arc::new(RouterRegistry::new(state, &[], &outbound)?);
    registry
        .create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            ManagedRouterProfile::new(
                "router".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                "admin".to_owned(),
                password,
            ),
        )
        .await?;
    let poller = Poller::with_intervals(
        registry,
        PollIntervals::new(
            Duration::from_secs(15),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(120),
        ),
    );
    let mut subscribers = Vec::new();
    for _index in 0..10 {
        subscribers.push(poller.subscribe("router").await);
    }
    for subscriber in &mut subscribers {
        timeout(Duration::from_secs(5), subscriber.changed()).await??;
        assert!(subscriber.borrow().as_ref().is_some_and(Result::is_ok));
    }
    assert_eq!(poller.light_rounds("router").await, 1);
    handle.shutdown().await?;
    Ok(())
}
