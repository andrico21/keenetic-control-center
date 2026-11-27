//! Realistic router answers that must pass the self-check, and the containment of the
//! identifiers list and of an existing capture directory.
//!
//! Assertion messages never carry a planted value.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking and is not rendered API documentation"
)]

use core::net::Ipv6Addr;
use std::fs;

use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::json;
use tempfile::TempDir;

use super::{
    leaks::{CAPTURE, log_line, serve},
    tests::{NAME, TestResult, all_text, percent_encoded, run_capture},
};

/// `--identifiers-out` given as a dangling file symlink into the capture directory is
/// refused, and nothing is written there (todo 4).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn identifiers_out_through_a_dangling_file_symlink_is_refused() -> TestResult {
    use std::os::unix::fs::symlink;

    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    let scratch = TempDir::new()?;
    let inside = scratch.path().join("out").join(CAPTURE).join("ids.txt");
    let link = scratch.path().join("fl.txt");
    symlink(&inside, &link)?;
    let output = run_capture(
        address,
        scratch.path(),
        &["--identifiers-out".to_owned(), link.display().to_string()],
    )
    .await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(1_i32), "refused");
    assert!(
        fs::symlink_metadata(&inside).is_err(),
        "nothing is written inside the capture"
    );
    Ok(())
}

/// Component names are protocol words: they pass the self-check and stay intact, also where
/// they are part of a fixed item name of the manifest (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn component_names_pass_the_self_check_intact() -> TestResult {
    let builder = FakeRouter::builder(Profile::default()).show_fixture(
        "components/list",
        json!([
            {"name": "wireguard", "installed": true},
            {"name": "sstp-server", "installed": false}
        ]),
    );
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(0_i32), "capture passes");
    let directory = scratch.path().join("out").join(CAPTURE);
    let components = fs::read_to_string(directory.join("components-list.json"))?;
    for name in ["\"wireguard\"", "\"sstp-server\""] {
        assert!(components.contains(name), "a component name is rewritten");
    }
    let manifest = fs::read_to_string(directory.join("manifest.json"))?;
    assert!(
        manifest.contains("\"show-rc-wireguard-server\""),
        "the fixed item name is kept"
    );
    Ok(())
}

/// Link-local IPv6 routes and gateways, which map to themselves, pass the self-check
/// (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn link_local_ipv6_routes_pass_the_self_check() -> TestResult {
    let builder = FakeRouter::builder(Profile::default()).show_fixture(
        "ipv6/route",
        json!([
            {"destination": "fe80::/64", "gateway": "::", "interface": "Bridge0"},
            {"destination": "::/0", "gateway": "fe80::1", "interface": "ISP"}
        ]),
    );
    let (address, handle) = serve(builder).await?;
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(0_i32), "capture passes");
    let routes = fs::read_to_string(
        scratch
            .path()
            .join("out")
            .join(CAPTURE)
            .join("show-ipv6-route.json"),
    )?;
    assert!(routes.contains("fe80::/64"), "the link-local route is kept");
    Ok(())
}

/// An existing capture directory holding a sub-directory and a non-UTF-8 file is refused:
/// the run fails and writes nothing into it, so a leak it would have carried never lands
/// (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn an_existing_capture_directory_is_refused() -> TestResult {
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    handle.insert_log(
        1,
        log_line(&format!("dhcp: lease for {}", percent_encoded(NAME)?)),
    );
    let scratch = TempDir::new()?;
    let directory = scratch.path().join("out").join(CAPTURE);
    fs::create_dir_all(directory.join("000"))?;
    fs::write(directory.join("stale.bin"), [0xff_u8, 0xfe])?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert!(!output.status.success(), "the run fails");
    let mut entries: Vec<String> = fs::read_dir(&directory)?
        .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    assert_eq!(entries, ["000", "stale.bin"], "nothing is written into it");
    Ok(())
}

/// A global IPv6 address glued to letters, after `addr:` or after `via` never survives:
/// the run rewrites it everywhere (exit 0) or fails and removes the capture (exit 3)
/// (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn glued_global_ipv6_addresses_never_survive() -> TestResult {
    let global = Ipv6Addr::new(
        0x2a02, 0x06b8, 0x1c2d, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f, 0x7a8b,
    )
    .to_string();
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    handle.insert_log(
        1,
        log_line(&format!(
            "{global}via \u{448}{global} addr:{global} via{global}"
        )),
    );
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    let out = scratch.path().join("out");
    let code = output.status.code();
    assert!(
        matches!(code, Some(0_i32 | 3_i32)),
        "unexpected exit {code:?}"
    );
    if code == Some(0_i32) {
        assert!(!all_text(&out)?.contains(&global), "the address survived");
    } else {
        assert!(!out.join(CAPTURE).exists(), "the capture is kept");
    }
    Ok(())
}

/// Log words with scope operators, link-local, loopback, multicast and documentation
/// addresses and MACs pass the self-check unchanged (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn realistic_address_shapes_pass_the_self_check() -> TestResult {
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    handle.insert_log(
        1,
        log_line(
            "Core::Authenticator: NDM::Something::x route fe80::/64 via fe80::1 lo ::1/128 \
             ff02::1 peer 2001:db8::5 mac 02:00:00:00:07:01 wireguard",
        ),
    );
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(0_i32), "capture passes");
    let log = fs::read_to_string(
        scratch
            .path()
            .join("out")
            .join(CAPTURE)
            .join("show-log.json"),
    )?;
    for word in [
        "Core::Authenticator:",
        "NDM::Something::x",
        "fe80::/64",
        "::1/128",
    ] {
        assert!(log.contains(word), "a log word is rewritten");
    }
    Ok(())
}

/// A FIFO as `--identifiers-out` is refused before the capture (exit 1) instead of
/// blocking the run (todo 4).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::disallowed_methods,
    reason = "the test creates a FIFO with mkfifo: the standard library cannot"
)]
async fn a_fifo_as_identifiers_out_is_refused() -> TestResult {
    use std::process::Command;

    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    let scratch = TempDir::new()?;
    let fifo = scratch.path().join("ids.fifo");
    let made = Command::new("mkfifo").arg(&fifo).status()?;
    assert!(made.success(), "mkfifo failed");
    let output = run_capture(
        address,
        scratch.path(),
        &["--identifiers-out".to_owned(), fifo.display().to_string()],
    )
    .await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(1_i32), "refused");
    assert!(
        !scratch.path().join("out").join(CAPTURE).exists(),
        "refused before the capture"
    );
    Ok(())
}
