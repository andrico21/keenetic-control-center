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

use core::{error::Error, str::FromStr as _, time::Duration};
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
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
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
        let router = FakeRouter::builder(profile).build()?;
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let client = connect(address).await?;
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
        let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
        let client = connect(address).await?;
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
    let (address, handle) = router.serve(([127, 0, 0, 1], 0).into()).await?;
    let client = connect(address).await?;
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

async fn connect(address: core::net::SocketAddr) -> Result<Arc<RciClient>, Box<dyn Error>> {
    let origin = RouterUrl::from_str(&format!("http://{address}"))?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    Ok(Arc::new(
        RciClient::connect_with(origin, credentials, options).await?,
    ))
}
