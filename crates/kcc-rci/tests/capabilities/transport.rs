//! Detection must use precisely the transport admitted by the outbound policy.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

use kcc_rci::{
    RciError, RouterUrl,
    auth::Credentials,
    capabilities::RouterInfo,
    outbound::{OutboundPolicy, TlsMode},
    session::{HttpTimeouts, Manager},
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use secrecy::SecretString;

use crate::{TestResult, tls_fixture::TlsFixture};

/// Opens a session with exactly the policy-approved address and TLS configuration.
fn manager(router: &RouterUrl, address: SocketAddr, tls: &TlsMode) -> TestResult<Manager> {
    let timeouts = HttpTimeouts::default();
    let builder = OutboundPolicy::default()
        .with_loopback(true)
        .client_builder_for_resolved(router, tls, timeouts, &[address])?;
    Ok(Manager::with_client_builder(
        router.clone(),
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD),
        ),
        timeouts,
        builder,
    )?)
}

/// A valid self-signed SPKI pin works for detection, including its initial auth probe.
// cancel-safe: the fixture aborts its tasks on drop and every router request is read-only.
#[tokio::test]
async fn detection_accepts_the_right_spki() -> TestResult {
    let fixture = TlsFixture::spawn().await?;
    let router = format!("https://127.0.0.1:{}", fixture.address().port()).parse()?;
    let session = manager(
        &router,
        fixture.address(),
        &TlsMode::PinSha256(fixture.fingerprint()),
    )?;
    session.ensure_session().await?;
    let result = RouterInfo::detect(&session, &router).await;
    fixture.shutdown().await;
    assert_eq!(result?.hw_id(), Some("KN-1811"));
    Ok(())
}

/// A wrong SPKI pin fails at the initial detection probe.
// cancel-safe: the fixture aborts its tasks on drop and no router configuration is changed.
#[tokio::test]
async fn detection_refuses_the_wrong_spki() -> TestResult {
    let fixture = TlsFixture::spawn().await?;
    let router = format!("https://127.0.0.1:{}", fixture.address().port()).parse()?;
    let session = manager(&router, fixture.address(), &TlsMode::PinSha256([0; 32]))?;
    let result = RouterInfo::detect(&session, &router).await;
    fixture.shutdown().await;
    assert!(matches!(result, Err(RciError::Transport)));
    Ok(())
}

/// The approved resolution survives a resolver returning a different address later.
// cancel-safe: all operations read the local fixture.
#[tokio::test]
async fn detection_keeps_the_approved_resolution() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let (changed_address, changed_handle) = FakeRouter::spawn().await?;
    let router = format!("http://router.invalid:{}", address.port()).parse()?;
    let resolver = Arc::new(ChangedResolver {
        address: changed_address,
        calls: AtomicUsize::new(0),
    });
    let builder = OutboundPolicy::default()
        .with_loopback(true)
        .client_builder_for_resolved(
            &router,
            &TlsMode::Verify,
            HttpTimeouts::default(),
            &[address],
        )?
        .dns_resolver(Arc::clone(&resolver))
        .pool_max_idle_per_host(0);
    let session = Manager::with_client_builder(
        router.clone(),
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD),
        ),
        HttpTimeouts::default(),
        builder,
    )?;
    let result = RouterInfo::detect(&session, &router).await;
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        0,
        "pinned addresses must bypass the changed resolver"
    );
    assert_eq!(changed_handle.request_count(), 0);
    changed_handle.shutdown().await?;
    handle.shutdown().await?;
    assert_eq!(result?.hw_id(), Some("KN-1811"));
    Ok(())
}

/// A separate probe origin cannot bypass the session's admitted destination.
// cancel-safe: all successful connections are to local fixtures.
#[tokio::test]
async fn detection_refuses_an_unapproved_probe_origin_without_sending() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let router = format!("http://router.invalid:{}", address.port()).parse()?;
    let session = manager(&router, address, &TlsMode::Verify)?;
    for target in [
        format!("http://{address}"),
        "http://169.254.169.254".to_owned(),
        "http://8.8.8.8".to_owned(),
    ] {
        let result = RouterInfo::detect(&session, &target.parse()?).await;
        assert!(matches!(result, Err(RciError::Policy)));
    }
    let requests = handle.request_count();
    handle.shutdown().await?;
    assert_eq!(requests, 0, "an unapproved probe must send nothing");
    Ok(())
}

/// A resolver whose answer differs from the policy-approved address.
struct ChangedResolver {
    /// Alternate local destination.
    address: SocketAddr,
    /// Lookups performed after policy admission.
    calls: AtomicUsize,
}

impl Resolve for ChangedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let _previous = self.calls.fetch_add(1, Ordering::SeqCst);
        let addresses: Addrs = Box::new([self.address].into_iter());
        Box::pin(async move { Ok(addresses) })
    }
}
