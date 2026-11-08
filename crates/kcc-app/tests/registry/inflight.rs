//! Server-observed request admission across registry client roles.

use core::{error::Error, time::Duration};
use std::fs;

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
extern crate alloc;

use alloc::sync::Arc;

use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RciPath, auth::Credentials};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Registry clients and dedicated background sessions share two server-side slots.
// NOT cancel-safe: a background start may leave remote work; the fake is isolated per test.
#[tokio::test]
async fn frontend_poller_and_background_share_two_inflight_slots() -> Result<(), Box<dyn Error>> {
    exercise(false).await
}

/// One standalone registry client retains its existing two-request limit.
// NOT cancel-safe: the isolated fake may retain a started background process until teardown.
#[tokio::test]
async fn one_client_keeps_two_inflight_slots() -> Result<(), Box<dyn Error>> {
    exercise(true).await
}

/// Exercises start, next, poll, and stop alongside both credential roles.
// NOT cancel-safe: background operations may have started on the isolated fixture.
async fn exercise(single_client: bool) -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let fake = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().latency(Duration::from_millis(80)))
        .build()?;
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let password = directory.path().join("password");
    fs::write(&password, DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let registry = RouterRegistry::new(
        StateStore::open(&directory.path().join("state"))?,
        &[],
        &outbound,
    )?;
    let mut profile = ManagedRouterProfile::new(
        "router".to_owned(),
        Url::parse(&format!("http://{address}"))?,
        "admin".to_owned(),
        password.clone(),
    );
    profile.read_login = Some("admin".to_owned());
    profile.read_password_file = Some(password);
    registry
        .create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            profile,
        )
        .await?;
    let front = if single_client {
        Arc::new(
            RciClient::connect_with(
                format!("http://{address}").parse()?,
                Credentials::new("admin".to_owned(), SecretString::from(DEFAULT_PASSWORD)),
                RciClientOptions::default()
                    .with_outbound(OutboundPolicy::default().with_loopback(true)),
            )
            .await?,
        )
    } else {
        registry.client("router").await?
    };
    let poll = if single_client {
        Arc::clone(&front)
    } else {
        registry.poll_client("router").await?
    };
    let path = RciPath::from_segments(["show", "system"])?;
    drop(front.get(&path, &()).await?);
    drop(poll.get(&path, &()).await?);
    if single_client {
        let (one, two, three, four) = tokio::join!(
            front.get(&path, &()),
            front.get(&path, &()),
            poll.get(&path, &()),
            poll.get(&path, &())
        );
        drop((one?, two?, three?, four?));
    } else {
        let body = json!({"host":"192.0.2.1"});
        let (one, two, three, four, started) = tokio::join!(
            front.get(&path, &()),
            front.get(&path, &()),
            poll.get(&path, &()),
            poll.get(&path, &()),
            front.start(RciPath::from_segments(["tools", "ping"])?, &body)
        );
        drop((one?, two?, three?, four?));
        let background = started?.with_poll_interval(Duration::ZERO);
        let (next_front, next_poll, next) = tokio::join!(
            front.get(&path, &()),
            poll.get(&path, &()),
            background.next()
        );
        drop((next_front?, next_poll?, next?));
        let token = CancellationToken::new();
        let (poll_front, poll_read, polled) = tokio::join!(
            front.get(&path, &()),
            poll.get(&path, &()),
            background.poll(&token)
        );
        drop((poll_front?, poll_read?, polled?));
        let stopping = front
            .start(RciPath::from_segments(["tools", "ping"])?, &body)
            .await?;
        let (stop_front, stop_poll, stopped) =
            tokio::join!(front.get(&path, &()), poll.get(&path, &()), stopping.stop());
        drop((stop_front?, stop_poll?, stopped?));
    }
    let maximum = handle.max_concurrent();
    handle.shutdown().await?;
    assert_eq!(
        maximum, 2,
        "server-side peak must remain two, including background traffic"
    );
    Ok(())
}
