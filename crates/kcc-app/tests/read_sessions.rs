//! A read-only polling login keeps one router session, shared and signed out cleanly.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration-test assertions and fixture setup"
)]

use core::{error::Error, time::Duration};
use std::sync::Arc;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;

/// Bound on waiting for the router to see a request.
const SEEN: Duration = Duration::from_secs(10);

/// Read-only login of the fixture.
const READER: &str = "reader";

/// A registry holding router `router` with a read-only login, and the fake router.
struct Fixture {
    registry: Arc<RouterRegistry>,
    router: Handle,
    profile: ManagedRouterProfile,
    admin: Role,
    _directory: TempDir,
}

impl Fixture {
    async fn open() -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let fake = FakeRouter::builder(Profile::default())
            .user(READER, DEFAULT_PASSWORD, ["readonly"])
            .build()?;
        let (address, router) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
        let read_password =
            kcc_testkit::write_secret_file(directory.path(), "read-password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(
            StateStore::open(&directory.path().join("state"))?,
            &[],
            &outbound,
        )?);
        let mut profile = ManagedRouterProfile::new(
            "router".to_owned(),
            Url::parse(&format!("http://{address}"))?,
            DEFAULT_LOGIN.to_owned(),
            password,
        );
        profile.read_login = Some(READER.to_owned());
        profile.read_password_file = Some(read_password);
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        registry.create(&admin, profile.clone()).await?;
        Ok(Self {
            registry,
            router,
            profile,
            admin,
            _directory: directory,
        })
    }

    /// Password sign-ins (`POST /auth`) the router has seen.
    fn logins(&self) -> usize {
        self.count("POST")
    }

    fn count(&self, method: &str) -> usize {
        self.router
            .request_log()
            .iter()
            .filter(|record| record.path() == "/auth" && record.method().as_str() == method)
            .count()
    }

    async fn signed_out(&self, count: usize) -> Result<(), Box<dyn Error>> {
        timeout(
            SEEN,
            self.router.wait_for_requests("DELETE", "/auth", count),
        )
        .await?;
        Ok(())
    }
}

/// SEC2-03 / B-06: repeated poll rounds, even concurrent ones, share one read-only session.
#[tokio::test]
async fn poll_rounds_share_one_read_only_session() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::open().await?;
    for _round in 0_u8..3 {
        let registry = &fixture.registry;
        let detections: [_; 4] = tokio::join!(
            registry.poll_info("router"),
            registry.poll_info("router"),
            registry.poll_info("router"),
            registry.poll_info("router"),
        )
        .into();
        for detected in detections {
            drop(detected?);
        }
    }

    assert_eq!(fixture.logins(), 1, "one sign-in for twelve polls");
    fixture.router.shutdown().await?;
    Ok(())
}

/// SEC2-03 / B-06: a profile update drops the cached session (signing it out) and the next
/// round signs in once more.
#[tokio::test]
async fn a_profile_update_replaces_the_read_only_session() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::open().await?;
    drop(fixture.registry.poll_info("router").await?);
    let mut edited = fixture.profile.clone();
    edited.tags = vec!["edited".to_owned()];
    fixture.registry.update(&fixture.admin, edited).await?;

    drop(fixture.registry.poll_info("router").await?);

    assert_eq!(fixture.logins(), 2);
    fixture.signed_out(1).await?;
    fixture.router.shutdown().await?;
    Ok(())
}

/// SEC2-03 / B-06: shutdown signs the cached read-only session out.
#[tokio::test]
async fn shutdown_logs_the_read_only_session_out() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::open().await?;
    drop(fixture.registry.poll_info("router").await?);
    assert_eq!(fixture.count("DELETE"), 0);

    fixture.registry.shutdown().await;

    assert_eq!(fixture.count("DELETE"), 1, "session closed on the router");
    fixture.router.shutdown().await?;
    Ok(())
}
