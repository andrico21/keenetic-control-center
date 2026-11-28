//! Diagnostics domain integration coverage.

#![expect(
    clippy::absolute_paths,
    clippy::assert_is_empty,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::shadow_unrelated,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::{error::Error, net::SocketAddr, str::FromStr as _, time::Duration};
use std::sync::Arc;

use kcc_app::{
    audit::AuditLog,
    jobs::{JobProgress, JobRunner, JobStatus},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
use kcc_catalog::Catalog;
use kcc_domain::diagnostics::{self, DiagnosticKind, ProgressLine};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::timeout;

use crate::support::PROFILES;

#[tokio::test]
async fn log_and_each_diagnostic_run_on_both_profiles() -> Result<(), Box<dyn Error>> {
    for firmware in PROFILES {
        let profile = Profile::new(Model::Kn1811, firmware)?;
        let router = FakeRouter::builder(profile).process_ids(true).build()?;
        let (endpoint, handle) = serve(router).await?;
        let client = connect(&endpoint).await?;
        assert!(
            diagnostics::read_log(&client, 20)
                .await?
                .contains("router log text")
        );

        for kind in [
            DiagnosticKind::Ping,
            DiagnosticKind::Ping6,
            DiagnosticKind::Traceroute,
            DiagnosticKind::Arping,
        ] {
            let path = kcc_rci::RciPath::from_segments(["tools", kind.name()])?;
            let handle = client
                .start(path, &json!({"host":"192.0.2.1"}))
                .await?
                .with_poll_interval(Duration::from_millis(1));
            let completed = handle
                .poll(&tokio_util::sync::CancellationToken::new())
                .await?;
            let kcc_rci::RciBody::Json(response) = completed else {
                panic!("diagnostic response must be JSON");
            };
            assert!(
                !diagnostics::typed_progress(
                    kind,
                    response
                        .value
                        .get("reply")
                        .unwrap_or(&serde_json::Value::Null)
                )
                .is_empty()
            );
        }

        let catalog = Catalog::for_firmware_and_model(firmware.title().parse()?, Some("KN-1811"))?;
        let iperf3_offered = diagnostics::DESCRIPTOR
            .available_writes(&catalog)
            .any(|operation| operation.name == "iperf3");
        assert_eq!(
            iperf3_offered,
            firmware == Firmware::V5_1,
            "iperf3 is offered only where the catalog documents `tools iperf3`"
        );
        if iperf3_offered {
            let path = kcc_rci::RciPath::from_segments(["tools", "iperf3"])?;
            let completed = client
                .start(path, &json!({"host":"192.0.2.1"}))
                .await?
                .with_poll_interval(Duration::from_millis(1))
                .poll(&tokio_util::sync::CancellationToken::new())
                .await?;
            let kcc_rci::RciBody::Json(response) = completed else {
                panic!("diagnostic response must be JSON");
            };
            assert!(matches!(
                diagnostics::typed_progress(
                    DiagnosticKind::Iperf3,
                    response
                        .value
                        .get("reply")
                        .unwrap_or(&serde_json::Value::Null)
                )
                .first(),
                Some(ProgressLine::Iperf3(_))
            ));
        }
        handle.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn diagnostic_job_emits_typed_output_line() -> Result<(), Box<dyn Error>> {
    for firmware in PROFILES {
        let profile = Profile::new(Model::Kn1811, firmware)?;
        let router = FakeRouter::builder(profile).build()?;
        let (endpoint, handle) = serve(router).await?;
        let client = connect(&endpoint).await?;
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &OutboundConfig::default(),
        )?);
        let jobs = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
        let mut events = jobs.subscribe();

        let id = diagnostics::start_job(
            &jobs,
            "router".to_owned(),
            client,
            DiagnosticKind::Ping,
            json!({"host":"192.0.2.1"}),
        )
        .await?;
        let emitted_output_line = timeout(Duration::from_secs(5), async {
            let mut emitted_output_line = false;
            loop {
                let event = events.recv().await?;
                if event.id != id {
                    continue;
                }
                if matches!(event.detail, Some(JobProgress::OutputLine(_))) {
                    emitted_output_line = true;
                }
                if event.status == JobStatus::Completed {
                    return Ok::<bool, tokio::sync::broadcast::error::RecvError>(
                        emitted_output_line,
                    );
                }
            }
        })
        .await??;

        assert!(emitted_output_line);
        assert_eq!(jobs.get(&id)?.status, JobStatus::Completed);
        handle.shutdown().await?;
    }
    Ok(())
}

/// Todo 28: a ping that continues in the session emits one `text` output line per string
/// of every chunk's `message`, in order: none is lost from the POST answer, the middle
/// chunks or the last chunk.
///
/// Real time: no paused clock with the fake's socket.
#[tokio::test]
async fn a_continued_ping_job_emits_one_text_line_per_message() -> Result<(), Box<dyn Error>> {
    let written = ["line 1", "line 2", "line 3", "line 4", "line 5"];
    let [first, second, third, fourth, fifth] = written;
    let profile = Profile::new(Model::Kn1811, PROFILES[0])?;
    let router = FakeRouter::builder(profile)
        .continued_fixture(
            "tools/ping",
            vec![
                json!({"message": [first, second], "continued": true}),
                json!({"message": [third], "continued": true}),
                json!({"continued": true}),
                json!({"message": [fourth, fifth]}),
            ],
        )
        .build()?;
    let (endpoint, handle) = serve(router).await?;
    let client = connect(&endpoint).await?;
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let jobs = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;
    let mut events = jobs.subscribe();

    let id = diagnostics::start_job(
        &jobs,
        "router".to_owned(),
        client,
        DiagnosticKind::Ping,
        json!({"host":"192.0.2.1"}),
    )
    .await?;
    let lines = timeout(Duration::from_secs(30), async {
        let mut lines = Vec::new();
        loop {
            let event = events.recv().await?;
            if event.id != id {
                continue;
            }
            if let Some(JobProgress::OutputLine(line)) = event.detail {
                lines.push(line);
            }
            if event.status != JobStatus::Running {
                return Ok::<_, tokio::sync::broadcast::error::RecvError>(lines);
            }
        }
    })
    .await??;

    let emitted: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<_, _>>()?;
    let expected: Vec<serde_json::Value> = written
        .iter()
        .map(|text| json!({"kind": "text", "text": text}))
        .collect();
    assert_eq!(emitted, expected);
    assert_eq!(jobs.get(&id)?.status, JobStatus::Completed);
    handle.shutdown().await?;
    Ok(())
}

/// C-19: a running diagnostic polls the router at the production interval, not every 10 ms.
///
/// The clock is paused, so the virtual time between the first and the last poll of one
/// ping is exactly the sum of the sleeps between them.
#[tokio::test(start_paused = true)]
async fn diagnostics_poll_the_router_at_the_production_interval() -> Result<(), Box<dyn Error>> {
    /// The fastest acceptable cadence between two polls of the router.
    const FASTEST: Duration = Duration::from_millis(500);
    let profile = Profile::new(Model::Kn1811, PROFILES[0])?;
    let router = FakeRouter::builder(profile).build()?;
    let (endpoint, handle) = serve(router).await?;
    let client = connect(&endpoint).await?;
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let jobs = JobRunner::open(state.clone(), registry, AuditLog::spawn(&state)?).await?;

    let _id = diagnostics::start_job(
        &jobs,
        "router".to_owned(),
        client,
        DiagnosticKind::Ping,
        json!({"host":"192.0.2.1"}),
    )
    .await?;
    handle.wait_for_requests("GET", "/rci/tools/ping", 1).await;
    let first = tokio::time::Instant::now();
    handle.wait_for_requests("GET", "/rci/tools/ping", 4).await;
    // The fake answers `continued` three times, so four polls are three sleeps apart.
    assert!(
        first.elapsed() >= FASTEST * 3,
        "four polls took only {:?} of router time",
        first.elapsed()
    );
    assert!(diagnostics::POLL_INTERVAL >= FASTEST);
    handle.shutdown().await?;
    Ok(())
}

/// Where a served fake router answers: the address of its URL and the outbound policy that
/// reaches it.
struct Endpoint {
    /// The address of the router URL.
    address: SocketAddr,
    /// Admits loopback and, on Unix, dials the fake's Unix socket for `address`.
    outbound: OutboundPolicy,
}

/// Serves `router` for every test here, paused clock or not.
///
/// On Unix it answers on a Unix socket: a paused clock can jump ahead of a loopback TCP
/// reply that is written but not yet readable.
// cancel-safe: dropping it drops the fake's handle, which stops the fake.
#[cfg_attr(
    unix,
    expect(
        clippy::unused_async,
        reason = "only the TCP fallback awaits; the Unix socket is served synchronously"
    )
)]
async fn serve(router: FakeRouter) -> Result<(Endpoint, Handle), Box<dyn Error>> {
    let loopback = OutboundPolicy::default().with_loopback(true);
    #[cfg(unix)]
    let (address, outbound, handle) = {
        let (address, socket, handle) = router.serve_local()?;
        (address, loopback.with_local_socket(address, socket), handle)
    };
    #[cfg(not(unix))]
    let ((address, handle), outbound) = (router.serve(([127, 0, 0, 1], 0).into()).await?, loopback);
    Ok((Endpoint { address, outbound }, handle))
}

/// Connects an RCI client to the fake router at `router`.
// cancel-safe: dropping it drops the half-connected client; the fake keeps no state for it.
async fn connect(router: &Endpoint) -> Result<Arc<RciClient>, Box<dyn Error>> {
    let origin = RouterUrl::from_str(&format!("http://{}", router.address))?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options = RciClientOptions::default().with_outbound(router.outbound.clone());
    Ok(Arc::new(
        RciClient::connect_with(origin, credentials, options).await?,
    ))
}
