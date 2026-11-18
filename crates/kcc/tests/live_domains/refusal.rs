//! Hermetic proof that the campaign writes nothing unless every write gate is open.
#![expect(clippy::panic_in_result_fn, reason = "refusal tests fail by asserting")]

use kcc_testkit::Handle;

use super::{TestResult, campaign, harness::Lab, live_gate::Refusal};

/// Requests that could change the router: anything but a GET, the login exchange, or a
/// `show` read; plus every parser line.
fn writes(handle: &Handle) -> Vec<String> {
    handle
        .request_log()
        .iter()
        .filter(|record| {
            let read = record.method() == "GET"
                || record.path() == "/auth"
                || record.path().starts_with("/rci/show");
            !read || record.command().is_some()
        })
        .map(|record| format!("{} {}", record.method(), record.path()))
        .collect()
}

/// Logs the request log as `METHOD path` lines for the QA evidence.
fn log_requests(label: &str, handle: &Handle) {
    let lines = handle
        .request_log()
        .iter()
        .map(|record| format!("{} {}", record.method(), record.path()))
        .collect::<Vec<_>>();
    tracing::info!(label, requests = lines.len(), log = ?lines, "request log");
}

/// `KCC_LIVE_ALLOW_WRITE` unset: every domain is read, and the router sees only reads.
#[tokio::test]
async fn read_only_campaign_performs_zero_writes() -> TestResult {
    drop(tracing_subscriber::fmt().with_test_writer().try_init());
    let lab = Lab::start(true).await?;
    let running = lab.handle.running_config_text();
    let report = campaign::run(lab.options(false, vec![lab.serial.clone()])).await?;
    log_requests("read-only", &lab.handle);
    assert!(!report.reads.is_empty(), "no domain was read");
    assert!(report.writes.is_empty(), "read-only run planned writes");
    assert_eq!(writes(&lab.handle), Vec::<String>::new(), "writes sent");
    assert_eq!(lab.handle.running_config_text(), running, "router changed");
    lab.handle.shutdown().await?;
    Ok(())
}

/// A profile without `test_device = true` is refused before the router is contacted.
#[tokio::test]
async fn profile_without_test_device_is_refused_before_contact() -> TestResult {
    let lab = Lab::start(false).await?;
    let contacts = lab.handle.request_count();
    let outcome = campaign::run(lab.options(true, vec![lab.serial.clone()])).await;
    let refusal = outcome
        .err()
        .and_then(|error| error.downcast_ref::<Refusal>().copied());
    assert_eq!(refusal, Some(Refusal::NotTestDevice));
    assert_eq!(
        lab.handle.request_count(),
        contacts,
        "gate contacted router"
    );
    lab.handle.shutdown().await?;
    Ok(())
}

/// T-08: a read-only campaign refuses a profile without `test_device = true`.
///
/// The refusal comes before the router receives a single request.
#[tokio::test]
async fn read_only_campaign_refuses_a_profile_without_test_device_before_contact() -> TestResult {
    let lab = Lab::start(false).await?;
    let contacts = lab.handle.request_count();
    let outcome = campaign::run(lab.options(false, vec![lab.serial.clone()])).await;
    let refusal = outcome
        .err()
        .and_then(|error| error.downcast_ref::<Refusal>().copied());
    assert_eq!(refusal, Some(Refusal::NotTestDevice));
    assert_eq!(
        lab.handle.request_count(),
        contacts,
        "gate contacted router"
    );
    lab.handle.shutdown().await?;
    Ok(())
}

/// A serial outside `KCC_LIVE_ALLOW_SERIAL` is refused after the identification read alone.
#[tokio::test]
async fn unlisted_serial_is_refused_with_zero_writes() -> TestResult {
    drop(tracing_subscriber::fmt().with_test_writer().try_init());
    let lab = Lab::start(true).await?;
    let before = lab.handle.request_log().len();
    let outcome = campaign::run(lab.options(true, vec!["S0000000000NOT".to_owned()])).await;
    log_requests("unlisted-serial", &lab.handle);
    let refusal = outcome
        .err()
        .and_then(|error| error.downcast_ref::<Refusal>().copied());
    assert_eq!(refusal, Some(Refusal::SerialNotAllowed));
    assert_eq!(writes(&lab.handle), Vec::<String>::new(), "writes sent");
    let reads = lab.handle.request_log().into_iter().skip(before);
    let paths = reads
        .filter(|record| record.path() != "/auth")
        .map(|record| record.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        ["/rci/show/identification"],
        "read beyond the serial"
    );
    lab.handle.shutdown().await?;
    Ok(())
}
