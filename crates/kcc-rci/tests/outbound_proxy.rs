//! Router clients connect straight to the pinned address whatever the proxy environment.
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

use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, auth::Credentials};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter};
use secrecy::SecretString;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

/// Set in the child run, which talks to the fake router under the proxy variables.
const CHILD_ENV: &str = "KCC_RCI_PROXY_CHILD";

/// Every proxy variable reqwest reads from the environment.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Detects the fake router through a loopback-admitting policy.
// NOT cancel-safe: owns the fake router until the detection finishes.
async fn detect_fake_router() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD),
    );
    let client =
        RciClient::connect_with(format!("http://{address}").parse()?, credentials, options).await?;
    drop(timeout(Duration::from_secs(15), client.detect()).await??);
    handle.shutdown().await?;
    Ok(())
}

/// SEC2-01: with `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` pointing at a listener, the
/// router client still reaches the router directly and the listener sees no connection.
#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "re-runs this test binary as a child with the proxy variables set"
)]
async fn router_client_ignores_proxy_environment() -> TestResult {
    if env::var_os(CHILD_ENV).is_some() {
        return detect_fake_router().await;
    }
    let proxy = TcpListener::bind("127.0.0.1:0")?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let mut command = ChildCommand::new(env::current_exe()?);
    let _: &mut ChildCommand = command
        .args([
            "--exact",
            "router_client_ignores_proxy_environment",
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
