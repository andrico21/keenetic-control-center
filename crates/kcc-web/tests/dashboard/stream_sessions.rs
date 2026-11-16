//! Event streams end with the session they belong to.
//!
//! Logout, an account disabled out of band, a reduced role and the session's absolute
//! lifetime each end an open stream, while a healthy stream keeps delivering.

use core::{str, time::Duration};

use axum::{body::BodyDataStream, http::StatusCode};
use futures_util::StreamExt as _;
use kcc_app::{
    accounts::AccountChange,
    permissions::{Permission, Role},
};
use kcc_web::sse::MAX_STREAMS_PER_SESSION;
use tokio::time::{Instant, timeout_at};

use crate::support::{
    outcome::TestResult,
    web::{Browser, Fixture},
};

/// How long after a session stops backing it a stream may still send.
const BOUND: Duration = Duration::from_secs(5);

/// The open-ended streams of the router pages: fleet, dashboard, router log and
/// interface traffic.
const STREAMS: [&str; 4] = [
    "/ui/sse/fleet",
    "/ui/sse/r/home/traffic",
    "/ui/sse/r/home/system/logs",
    "/ui/sse/r/home/network/traffic?name=Bridge0",
];

/// `path` opened as the fixture's `browser`, once its first event arrived.
async fn opened(fixture: &Fixture, browser: &Browser, path: &str) -> TestResult<BodyDataStream> {
    let response = fixture.get(path, browser).await?;
    assert_eq!(response.status(), StatusCode::OK, "{path}: stream opened");
    let mut body = response.into_body().into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or("deadline overflow")?;
    let mut received = String::new();
    while !received.contains("event: ") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or_else(|| format!("{path}: ended before its first event"))??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    Ok(body)
}

/// How long `body` took to end from now; an error when it still sends after `bound`.
async fn ended(body: &mut BodyDataStream, bound: Duration) -> TestResult<Duration> {
    let start = Instant::now();
    let deadline = start
        .checked_add(bound.saturating_add(Duration::from_secs(1)))
        .ok_or("deadline overflow")?;
    while timeout_at(deadline, body.next())
        .await?
        .transpose()?
        .is_some()
    {}
    Ok(start.elapsed())
}

/// SEC1-06, W1-02, W5-02: logging out ends every open stream of the session (fleet,
/// dashboard, router log and interface traffic) within the re-check bound.
#[tokio::test(start_paused = true)]
async fn logout_ends_every_open_stream_of_the_session() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let mut bodies = Vec::new();
    for path in STREAMS {
        bodies.push((path, opened(&fixture, &browser, path).await?));
    }

    let logout = fixture.post("/ui/logout", &browser, "").await?;
    assert!(
        logout.status().is_success() || logout.status().is_redirection(),
        "logged out: {}",
        logout.status()
    );

    for (path, body) in &mut bodies {
        let took = ended(body, BOUND).await?;
        assert!(took <= BOUND, "{path}: ended after {took:?}");
    }
    Ok(())
}

/// SEC1-06, W1-02, W5-02: an account disabled in `users.json` ends its open stream once
/// the state watcher's pass ends the session.
#[tokio::test(start_paused = true)]
async fn disabling_the_account_ends_its_open_stream() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let mut body = opened(&fixture, &browser, "/ui/sse/fleet").await?;

    let before = fixture
        .accounts()
        .administer("viewer", &AccountChange::Disabled(true))?;
    assert!(before.is_some(), "the account existed");
    let (_, sessions) = fixture.state().end_stale_sessions().await?;
    assert_eq!(sessions, 1, "the watcher's pass ended the viewer's session");

    let took = ended(&mut body, BOUND).await?;
    assert!(took <= BOUND, "ended after {took:?}");
    Ok(())
}

/// SEC1-06, W1-02, W5-02: a role reduced by a reload (the session itself stays) ends the
/// stream of a router the role no longer reaches, and the ended stream gives its slot
/// back to the session.
#[tokio::test(start_paused = true)]
async fn a_reduced_role_ends_the_stream_and_frees_its_slot() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let mut body = opened(&fixture, &browser, "/ui/sse/r/home/traffic").await?;

    let reduced = fixture
        .roles()
        .current()
        .iter()
        .map(|role| {
            if role.name == "viewer" {
                Role::new(
                    role.name.clone(),
                    [Permission::Read],
                    vec!["lab-*".to_owned()],
                )
            } else {
                role.clone()
            }
        })
        .collect();
    fixture.roles().replace(reduced);

    let took = ended(&mut body, BOUND).await?;
    assert!(took <= BOUND, "ended after {took:?}");
    let mut fleet = Vec::new();
    for _ in 0..MAX_STREAMS_PER_SESSION {
        let response = fixture.get("/ui/sse/fleet", &browser).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the ended stream released its slot"
        );
        fleet.push(response);
    }
    assert_eq!(
        fleet.len(),
        MAX_STREAMS_PER_SESSION,
        "every slot open at once"
    );
    Ok(())
}

/// SEC1-06, W1-02: a stream opened ten seconds before its session's absolute expiry ends
/// at that expiry, not earlier and not later.
#[tokio::test(start_paused = true)]
async fn a_stream_ends_at_its_session_absolute_expiry() -> TestResult {
    let fixture = Fixture::new().await?;
    let signed_in = 1_700_000_000_u64;
    let browser = fixture.login("viewer").await?;
    for step in 1..=10_u64 {
        fixture.clock().set(signed_in + step * 3_599);
        let page = fixture.get("/ui/account", &browser).await?;
        assert_eq!(page.status(), StatusCode::OK, "still signed in at {step}");
    }
    let opened_at = Instant::now();
    let mut body = opened(&fixture, &browser, "/ui/sse/fleet").await?;

    let _: Duration = ended(&mut body, Duration::from_secs(10)).await?;
    let lived = opened_at.elapsed();
    assert!(
        lived >= Duration::from_secs(10) && lived <= Duration::from_secs(11),
        "ended {lived:?} after opening, the session had 10 s left"
    );
    Ok(())
}

/// W5-02: a stream whose session stays valid keeps delivering across many re-checks.
#[tokio::test(start_paused = true)]
async fn a_healthy_stream_keeps_delivering_past_its_re_checks() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let mut body = opened(&fixture, &browser, "/ui/sse/fleet").await?;
    let start = Instant::now();
    let deadline = start
        .checked_add(Duration::from_secs(61))
        .ok_or("deadline overflow")?;
    let mut cards = 0_usize;
    while cards < 3 {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended early")??;
        cards = cards.saturating_add(
            str::from_utf8(&chunk)?
                .matches("event: router-home")
                .count(),
        );
    }
    assert!(
        start.elapsed() >= Duration::from_secs(30),
        "three polls span at least six re-checks: {:?}",
        start.elapsed()
    );
    Ok(())
}
