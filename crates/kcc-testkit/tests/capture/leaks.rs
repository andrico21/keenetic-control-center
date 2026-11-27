//! Leak paths of `kcc-capture` against the fake router.
//!
//! Case and script variants, the manifest, a single item file, `--identifiers-out`
//! containment, secrets, the serial read and the self-ping target. Assertion messages never
//! carry a planted value.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking and is not rendered API documentation"
)]

use core::{error::Error, net::SocketAddr};
use std::{fs, process::Output};

use axum::http::Method;
use kcc_testkit::{FakeRouter, FakeRouterBuilder, FaultInjection, Handle, model::Profile};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::tests::{NAME, TestResult, all_text, percent_encoded, run_capture};

/// A planted name in another script.
const CYRILLIC: &str =
    "\u{41a}\u{443}\u{445}\u{43d}\u{44f} \u{410}\u{43d}\u{434}\u{440}\u{435}\u{44f}";
/// A planted SSID.
const SSID: &str = "PlantedSsid";
/// A planted interface id that is also a learned description.
const IFACE: &str = "PLANTED-IFACE-21";
/// A planted `show rc user` password.
const SECRET: &str = "PLANTED-SECRET-31";
/// The capture directory the fake router's identity yields.
pub(super) const CAPTURE: &str = "KN-1811-5.1.3";

/// A fake router built from `builder` whose `show ip arp` lists one client holding the
/// planted name, the non-ASCII name and the SSID.
pub(super) async fn serve(
    builder: FakeRouterBuilder,
) -> Result<(SocketAddr, Handle), Box<dyn Error>> {
    let row = json!({
        "mac": "02:00:00:00:07:01", "ip": "192.0.2.77", "name": NAME,
        "hostname": CYRILLIC, "ssid": SSID,
    });
    Ok(builder
        .show_fixture("ip/arp", json!([row]))
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?)
}

/// A router log record carrying `message`.
pub(super) fn log_line(message: &str) -> Value {
    json!({"message": {"label": "I", "message": message}})
}

/// The stderr of `output`, lowercased.
fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_lowercase()
}

/// Case variants, glued variants and non-ASCII names are rewritten, and the non-ASCII name
/// reaches `--identifiers-out` (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn variants_and_non_ascii_names_are_rewritten_and_listed() -> TestResult {
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    let lower = NAME.to_lowercase();
    handle.insert_log(
        1,
        log_line(&format!(
            "lease {lower}_laptop; x{lower} {NAME}-pc {} joined {}5g",
            CYRILLIC.to_uppercase(),
            SSID.to_lowercase()
        )),
    );
    let scratch = TempDir::new()?;
    let identifiers = scratch.path().join("identifiers.txt");
    let output = run_capture(
        address,
        scratch.path(),
        &[
            "--identifiers-out".to_owned(),
            identifiers.display().to_string(),
        ],
    )
    .await?;
    handle.shutdown().await?;
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let written = all_text(&scratch.path().join("out"))?;
    for (index, planted) in [NAME, CYRILLIC, SSID].into_iter().enumerate() {
        assert!(
            !written.contains(&planted.to_lowercase()),
            "planted value {index} survived"
        );
    }
    let listed = fs::read_to_string(&identifiers)?;
    assert!(
        listed.lines().any(|line| line == CYRILLIC),
        "the non-ASCII name is listed"
    );
    Ok(())
}

/// A learned value only in the manifest (the name of a skipped item) fails the self-check
/// (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn a_learned_value_only_in_the_manifest_fails_the_self_check() -> TestResult {
    let builder = FakeRouter::builder(Profile::default())
        .show_fixture(
            "interface",
            json!({IFACE: {"id": IFACE, "description": IFACE}}),
        )
        .faults(FaultInjection::default().fail_read_matching("interface/stat", 5));
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(3_i32), "leak exit");
    assert!(
        !scratch.path().join("out").join(CAPTURE).exists(),
        "the capture directory is removed"
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("manifest.json"), "the manifest is named");
    assert!(!stderr.contains(&IFACE.to_lowercase()), "no value printed");
    Ok(())
}

/// A leak in exactly one item file fails the self-check and names that item (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn a_leak_in_one_item_file_fails_the_self_check() -> TestResult {
    let builder = FakeRouter::builder(Profile::default()).show_fixture(
        "ntp/status",
        json!({"server": format!("pool?n={}", percent_encoded(NAME)?)}),
    );
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(3_i32), "leak exit");
    assert!(
        !scratch.path().join("out").join(CAPTURE).exists(),
        "the capture directory is removed"
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("show-ntp-status"), "the item is named");
    assert!(!stderr.contains(&NAME.to_lowercase()), "no value printed");
    Ok(())
}

/// `--identifiers-out` through a dangling symlink to the capture directory is refused once
/// that directory exists (todo 4).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn identifiers_out_through_a_dangling_symlink_is_refused() -> TestResult {
    use std::os::unix::fs::symlink;

    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    let scratch = TempDir::new()?;
    let capture = scratch.path().join("out").join(CAPTURE);
    symlink(&capture, scratch.path().join("link"))?;
    let target = scratch.path().join("link").join("identifiers.txt");
    let output = run_capture(
        address,
        scratch.path(),
        &["--identifiers-out".to_owned(), target.display().to_string()],
    )
    .await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(1_i32), "refused");
    assert!(
        !capture.join("identifiers.txt").exists(),
        "no identifiers file inside the capture"
    );
    assert!(
        !stderr_of(&output).contains(&NAME.to_lowercase()),
        "no value printed"
    );
    Ok(())
}

/// Secrets never reach `--identifiers-out` nor the capture (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn secrets_never_reach_identifiers_out() -> TestResult {
    let builder = FakeRouter::builder(Profile::default()).rc_fixture(
        "/user",
        json!({"planted-login": {"password": {"md5": SECRET}, "tag": ["cli"]}}),
    );
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let identifiers = scratch.path().join("identifiers.txt");
    let output = run_capture(
        address,
        scratch.path(),
        &[
            "--identifiers-out".to_owned(),
            identifiers.display().to_string(),
        ],
    )
    .await?;
    handle.shutdown().await?;
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let listed = fs::read_to_string(&identifiers)?;
    assert!(
        listed.lines().any(|line| line == "planted-login"),
        "the user name is listed"
    );
    assert!(!listed.contains(SECRET), "the secret is not listed");
    let written = all_text(&scratch.path().join("out"))?;
    assert!(!written.contains(&SECRET.to_lowercase()), "secret written");
    Ok(())
}

/// The serial check reads `show identification` with GET only (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn serial_check_never_posts_show_identification() -> TestResult {
    let builder = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().show_requires_post("show/identification"));
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    let log = handle.request_log();
    handle.shutdown().await?;
    assert!(!output.status.success(), "no serial, no capture");
    assert!(
        !log.iter()
            .any(|record| record.method() == Method::POST
                && record.path() == "/rci/show/identification"),
        "no POST of show identification"
    );
    assert!(
        log.iter()
            .any(|record| record.method() == Method::GET
                && record.path() == "/rci/show/identification"),
        "the serial is read with GET"
    );
    Ok(())
}

/// The self-ping targets the router URL's own host with at most three echoes (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn self_ping_targets_the_router_host_with_a_small_count() -> TestResult {
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    let log = handle.request_log();
    handle.shutdown().await?;
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let pings: Vec<Vec<String>> = log
        .iter()
        .filter(|record| record.method() == Method::POST && record.path() == "/rci/tools/ping")
        .map(|record| {
            record
                .command()
                .unwrap_or_default()
                .split(' ')
                .map(str::to_owned)
                .collect()
        })
        .collect();
    assert_eq!(pings.len(), 1, "one self-ping");
    let words = pings.first().cloned().unwrap_or_default();
    let after = |key: &str| {
        words
            .iter()
            .position(|word| word == key)
            .and_then(|index| words.get(index.saturating_add(1)))
            .cloned()
    };
    assert_eq!(
        after("host"),
        Some(address.ip().to_string()),
        "the ping targets the router host: {words:?}"
    );
    let count = after("count").and_then(|text| text.parse::<u8>().ok());
    assert!(
        count.is_some_and(|echoes| (1..=3).contains(&echoes)),
        "at most three echoes: {words:?}"
    );
    Ok(())
}
