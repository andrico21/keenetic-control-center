//! Address spellings in a router log line through the whole `kcc-capture` run.
//!
//! Global addresses joined to link-local or multicast groups, a multicast group embedding
//! the prefix, and a public IPv4 address dashed in host names, zero-padded or with a port.
//!
//! Addresses are built at run time. Assertion messages never carry a planted value.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking and is not rendered API documentation"
)]

use core::net::{Ipv4Addr, Ipv6Addr};

use kcc_testkit::{FakeRouter, model::Profile};
use tempfile::TempDir;

use super::{
    leaks::{log_line, serve},
    tests::{TestResult, all_text, run_capture},
};

/// Every spelling of a learned IPv4 address and every group of a global `/48` is rewritten
/// in the log, so the run passes with none of them in any written file (todo 4).
#[tokio::test(flavor = "multi_thread")]
async fn address_spellings_in_a_log_line_never_survive() -> TestResult {
    let global = Ipv6Addr::new(
        0x2a02, 0x06b8, 0x1c2d, 0x3e4f, 0x1a2b, 0x3c4d, 0x5e6f, 0x7a8b,
    );
    let [first, second, third, ..] = global.segments();
    let prefix = format!("{first:x}:{second:x}:{third:x}");
    let octets = [81_u8, 2, 69, 160];
    let dotted = Ipv4Addr::from(octets).to_string();
    let dashed = octets.map(|octet| octet.to_string()).join("-");
    let padded = octets.map(|octet| format!("{octet:03}")).join(".");
    let (address, handle) = serve(FakeRouter::builder(Profile::default())).await?;
    handle.insert_log(
        1,
        log_line(&format!(
            "fe80:{global} ff02:{global} join ff3e:40:{prefix}:1::1 \
             host-{dashed}.isp.example {dashed}.static.example {padded} \
             {dotted}.443 {dotted}:8080"
        )),
    );
    let scratch = TempDir::new()?;
    let output = run_capture(address, scratch.path(), &[]).await?;
    handle.shutdown().await?;
    assert_eq!(output.status.code(), Some(0_i32), "the run passes");
    let written = all_text(&scratch.path().join("out"))?;
    for (index, spelling) in [prefix, format!(":{third:x}:"), dotted, dashed, padded]
        .iter()
        .enumerate()
    {
        assert!(
            !written.contains(spelling.as_str()),
            "spelling {index} survived"
        );
    }
    Ok(())
}
