//! Termination and the rebind of a previous generation after a failed restart.

extern crate alloc;

use alloc::sync::Arc;
use core::{future::pending, net::SocketAddr, time::Duration};
use std::net::{TcpListener, TcpStream};

use kcc_app::{
    mcp_settings::{ListenerKind, document::McpOverrides},
    settings::mcp_schema::Endpoint,
};
use reqwest::StatusCode;

use super::{
    SHORT, TestResult, bounded,
    client::{http, initialize_status},
    endpoint,
    fixture::{Fixture, Setup, free_port},
    holding,
};
use crate::{
    server_error::ServerError,
    server_listeners::{
        ListenerError, ListenerSupervisor, Restarted, RevertReason,
        build::{Built, Keys, build},
        supervisor::{Stage, Supervisor, Windows},
    },
};

/// Whether something accepts connections at `address`.
fn accepts(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok()
}

/// A fixture whose dedicated listener serves on a free port, holding `stages`.
async fn with_dedicated(
    stages: &[Stage],
    windows: Windows,
) -> TestResult<(Fixture, super::Holds, u16)> {
    let (hook, holds) = holding(stages);
    let port = free_port()?;
    let fixture = Fixture::start(Setup {
        tail: format!("[mcp.dedicated]\nenabled = true\nport = {port}\n"),
        hook,
        windows: Some(windows),
        ..Setup::default()
    })
    .await?;
    Ok((fixture, holds, port))
}

/// A change moving the dedicated listener to `port`.
fn dedicated_port(port: u16) -> McpOverrides {
    let mut change = McpOverrides::default();
    change.dedicated.port = Some(port);
    change
}

/// Todo 26: a termination while a restart is held open, with another restart queued,
/// stops every generation, starts none, and both restarts end with `ShuttingDown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_termination_during_a_restart_stops_every_generation() -> TestResult {
    let (hook, mut holds) = holding(&[Stage::Serving]);
    let fixture = Fixture::start(Setup {
        hook,
        ..Setup::default()
    })
    .await?;
    let main = fixture.main()?;
    let held = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&endpoint(Endpoint::Both))?),
    );
    let queued = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&endpoint(Endpoint::Main))?),
    );
    drop(holds.until(Stage::Serving).await?);
    let supervisor = fixture.supervisor.clone();

    let stopped = bounded(fixture.stop()).await??;

    assert!(stopped.is_ok(), "{stopped:?}");
    assert!(matches!(
        bounded(held).await??,
        Err(ListenerError::ShuttingDown)
    ));
    assert!(matches!(
        bounded(queued).await??,
        Err(ListenerError::ShuttingDown)
    ));
    assert_eq!(supervisor.status().main, None);
    assert!(!accepts(main), "the new main generation still serves");
    Ok(())
}

/// Todo 26: a termination while the previous generation's address is still held, so its
/// rebind retries, stops the supervisor at once with no generation left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_termination_wins_over_a_rebind_in_progress() -> TestResult {
    let long = Windows {
        rebind: Duration::from_secs(30),
        ..SHORT
    };
    let (fixture, mut holds, old) = with_dedicated(&[Stage::Stopped, Stage::Rebind], long).await?;
    let moved = TcpListener::bind(("127.0.0.1", 0))?;
    let restart = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&dedicated_port(moved.local_addr()?.port()))?),
    );
    drop(holds.until(Stage::Stopped).await?);
    let previous = TcpListener::bind(("127.0.0.1", old))?;
    holds.release()?;
    drop(holds.until(Stage::Rebind).await?);
    let supervisor = fixture.supervisor.clone();

    let stopped = bounded(fixture.stop()).await??;

    assert!(stopped.is_ok(), "{stopped:?}");
    assert!(matches!(
        bounded(restart).await??,
        Err(ListenerError::ShuttingDown)
    ));
    assert_eq!(
        (supervisor.status().main, supervisor.status().dedicated),
        (None, None)
    );
    drop((previous, moved));
    Ok(())
}

/// Todo 26: a previous generation whose address is still in use is bound again once it
/// is free, within the rebind window: the restart reverts and the old listener serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_rebind_retries_until_the_previous_address_is_free() -> TestResult {
    let (fixture, mut holds, old) = with_dedicated(&[Stage::Stopped, Stage::Rebind], SHORT).await?;
    let moved = TcpListener::bind(("127.0.0.1", 0))?;
    let restart = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&dedicated_port(moved.local_addr()?.port()))?),
    );
    drop(holds.until(Stage::Stopped).await?);
    let previous = TcpListener::bind(("127.0.0.1", old))?;
    holds.release()?;
    drop(holds.until(Stage::Rebind).await?);
    drop(previous);
    holds.release_all()?;

    let restarted = bounded(restart).await???;
    assert!(
        matches!(
            restarted,
            Restarted::Reverted(RevertReason::Bind {
                listener: ListenerKind::Dedicated,
                reason: _,
            })
        ),
        "{restarted:?}"
    );
    assert_eq!(fixture.dedicated()?.port(), old);
    assert_eq!(
        initialize_status(&http()?, fixture.dedicated()?, &fixture.key).await?,
        StatusCode::OK
    );
    drop(moved);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a previous generation that cannot bind again within the rebind window stops
/// `kcc serve` with an error, the main listener included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_rebind_stops_with_an_error() -> TestResult {
    let (fixture, mut holds, old) = with_dedicated(&[Stage::Stopped], SHORT).await?;
    let main = fixture.main()?;
    let moved = TcpListener::bind(("127.0.0.1", 0))?;
    let restart = tokio::spawn(
        fixture
            .supervisor
            .restart(fixture.plan(&dedicated_port(moved.local_addr()?.port()))?),
    );
    drop(holds.until(Stage::Stopped).await?);
    let previous = TcpListener::bind(("127.0.0.1", old))?;
    holds.release_all()?;

    assert!(matches!(
        bounded(restart).await??,
        Err(ListenerError::ShuttingDown)
    ));
    let stopped = bounded(fixture.serving).await??;
    assert!(
        matches!(
            stopped,
            Err(ServerError::Rebind {
                listener: "dedicated",
                reason: _
            })
        ),
        "{stopped:?}"
    );
    assert!(!accepts(main), "the main listener still serves");
    drop((previous, moved));
    Ok(())
}

/// Todo 26: a listener whose kit server returns on its own while no change runs stops the
/// supervisor, which returns the listener's error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_that_returns_on_its_own_stops_the_supervisor() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let files = tempfile::TempDir::new()?;
    let absent = files.path().join("absent.pem");
    let built = build(
        &fixture.shared,
        ListenerKind::Main,
        &fixture.saved()?,
        Keys::Required,
    )?;
    let failing = Built {
        config: built
            .config
            .into_inner()
            .with_tls_paths(Some(absent.clone()), Some(absent))
            .validate()?,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..built
    };
    let (_handle, queue, status) = ListenerSupervisor::channel();
    let mut supervisor = Supervisor::new(Arc::clone(&fixture.shared), fixture.effective()?, status);
    let _address = supervisor
        .listeners
        .start(failing, None)
        .await
        .map_err(|_failed| "the kit server did not report its address")?;

    let stopped = bounded(supervisor.serve(queue, pending::<()>())).await?;

    assert!(matches!(stopped, Err(ServerError::Kit(_))), "{stopped:?}");
    fixture.stop().await??;
    Ok(())
}
