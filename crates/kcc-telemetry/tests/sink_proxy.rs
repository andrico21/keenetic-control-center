//! Log sinks connect straight to their destination whatever the proxy environment.
//!
//! The test re-runs itself as a child process with the proxy variables set, so the
//! variables never touch this process's environment.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration-test crate: the test drives a copy of itself in a child process"
)]

use core::{error::Error, time::Duration};
use std::{env, io::ErrorKind, net::TcpListener, process::Command as ChildCommand};

use chrono::{FixedOffset, TimeZone as _};
use kcc_app::settings::Config;
use kcc_telemetry::logs::{elastic_sink::ElasticsearchClient, sink::LokiClient, types::LogRecord};
use kcc_testkit::{fake_elasticsearch::FakeElasticsearch, fake_loki::FakeLoki};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

/// Set in the child run, which delivers to the fake sinks under the proxy variables.
const CHILD_ENV: &str = "KCC_SINK_PROXY_CHILD";

/// Every proxy variable reqwest reads from the environment.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Bound on one delivery; a proxied request never gets an answer.
const DELIVERY: Duration = Duration::from_secs(15);

/// Delivers one record to a fake Loki and a fake Elasticsearch.
// NOT cancel-safe: owns both fakes until both deliveries finish.
async fn deliver_to_fake_sinks() -> TestResult {
    let loki = FakeLoki::spawn().await?;
    let search = FakeElasticsearch::spawn().await?;
    let config = Config::from_toml_str(&format!(
        "[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n\n[[logs.sinks]]\nkind = \"elasticsearch\"\nurl = \"{}\"\n",
        loki.url(),
        search.url()
    ))?;
    config.validate()?;
    let timestamp = FixedOffset::east_opt(0)
        .ok_or("offset")?
        .with_ymd_and_hms(2026, 11, 6, 12, 0, 1)
        .single()
        .ok_or("date")?;
    let records = [LogRecord::new(
        "home".to_owned(),
        1,
        timestamp,
        "info".to_owned(),
        "direct".to_owned(),
    )];
    let loki_sink = LokiClient::load(config.logs.sinks.first().ok_or("loki sink")?).await?;
    let search_sink =
        ElasticsearchClient::load(config.logs.sinks.get(1).ok_or("search sink")?).await?;

    timeout(DELIVERY, loki_sink.send(&records)).await??;
    drop(timeout(DELIVERY, search_sink.send(&records)).await??);

    assert_eq!(loki.requests().len(), 1, "Loki got the batch directly");
    assert_eq!(
        search.requests().len(),
        1,
        "Elasticsearch got the batch directly"
    );
    loki.shutdown().await?;
    search.shutdown().await?;
    Ok(())
}

/// SEC2-01: with `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` pointing at a listener, the
/// Loki and Elasticsearch sinks still deliver directly and the listener sees no connection.
#[tokio::test]
async fn log_sinks_ignore_proxy_environment() -> TestResult {
    if env::var_os(CHILD_ENV).is_some() {
        return deliver_to_fake_sinks().await;
    }
    let proxy = TcpListener::bind("127.0.0.1:0")?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let mut command = ChildCommand::new(env::current_exe()?);
    let _: &mut ChildCommand = command
        .args([
            "--exact",
            "log_sinks_ignore_proxy_environment",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for variable in PROXY_VARIABLES {
        let _: &mut ChildCommand = command.env(variable, &proxy_url);
    }

    let output = command.output()?;

    assert!(
        output.status.success(),
        "child run failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    proxy.set_nonblocking(true)?;
    let pending = proxy.accept();
    assert!(
        matches!(&pending, Err(error) if error.kind() == ErrorKind::WouldBlock),
        "the proxy listener saw a connection"
    );
    Ok(())
}
