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

use core::{error::Error, str::FromStr as _, time::Duration};
use std::sync::Arc;

use kcc_app::{
    jobs::{JobProgress, JobRunner, JobStatus},
    persist::StateStore,
    registry::RouterRegistry,
    settings::OutboundConfig,
};
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

#[tokio::test]
async fn log_and_each_diagnostic_run_on_both_profiles() -> Result<(), Box<dyn Error>> {
    for firmware in [Firmware::V4_3, Firmware::V5_1] {
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

        if firmware == Firmware::V5_1 {
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
    let profile = Profile::new(Model::Kn1811, Firmware::V5_1)?;
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
    let jobs = JobRunner::open(state, registry).await?;
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
                return Ok::<bool, tokio::sync::broadcast::error::RecvError>(emitted_output_line);
            }
        }
    })
    .await??;

    assert!(emitted_output_line);
    assert_eq!(jobs.get(&id)?.status, JobStatus::Completed);
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
