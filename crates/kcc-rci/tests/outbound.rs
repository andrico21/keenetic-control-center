//! Outbound policy regression tests.

#![expect(
    clippy::missing_errors_doc,
    reason = "test functions propagate fixture errors"
)]
#![expect(
    clippy::missing_panics_doc,
    reason = "test assertions report regressions"
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report regressions"
)]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this file is an integration-test crate"
)]

use core::{
    error::Error,
    net::{IpAddr, SocketAddr},
};

use kcc_rci::{AllowedNetwork, OutboundPolicy, RouterUrl, TlsMode, session::HttpTimeouts};

type TestResult = Result<(), Box<dyn Error>>;

/// Builds the policy result for one synthetic DNS answer.
///
/// # Errors
/// Returns URL parsing or outbound-policy failures.
fn admitted(policy: &OutboundPolicy, host: &str, address: IpAddr) -> TestResult {
    let router = format!("http://{host}").parse::<RouterUrl>()?;
    let resolved = [SocketAddr::new(address, 80)];
    policy
        .client_builder_for_resolved(
            &router,
            &TlsMode::Verify,
            HttpTimeouts::default(),
            &resolved,
        )
        .map(drop)
        .map_err(Into::into)
}

#[test]
fn suffix_path_admits_only_global_addresses_and_exact_domain_boundaries() -> TestResult {
    let policy = OutboundPolicy::default()
        .with_allowed_networks(Vec::new())
        .with_allowed_suffixes(vec![".keenetic.pro".to_owned()]);
    let ten = format!("{}.0.0.1", 10_u8);
    let cases = [
        ("127.0.0.1", false),
        ("::1", false),
        ("::ffff:127.0.0.1", false),
        ("0.0.0.0", false),
        ("::", false),
        ("169.254.169.254", false),
        ("::ffff:169.254.169.254", false),
        ("fd00::1", false),
        (ten.as_str(), false),
        ("192.168.1.1", false),
        ("8.8.8.8", true),
    ];

    for (text, expected) in cases {
        let address = text.parse::<IpAddr>()?;
        assert_eq!(
            admitted(&policy, "router.keenetic.pro", address).is_ok(),
            expected,
            "suffix decision for {address}"
        );
    }
    admitted(&policy, "keenetic.pro", "8.8.8.8".parse()?)?;
    assert!(admitted(&policy, "evilkeenetic.pro", "8.8.8.8".parse()?).is_err());
    Ok(())
}

#[test]
fn network_path_canonicalizes_addresses_and_honors_loopback_separately() -> TestResult {
    let networks = vec![
        AllowedNetwork::new("10.0.0.0".parse()?, 8)?,
        AllowedNetwork::new("192.168.0.0".parse()?, 16)?,
        AllowedNetwork::new("0.0.0.0".parse()?, 0)?,
        AllowedNetwork::new("::".parse()?, 0)?,
    ];
    let denied = OutboundPolicy::default()
        .with_allowed_networks(networks.clone())
        .with_allowed_suffixes(Vec::new());
    let allowed = OutboundPolicy::default()
        .with_allowed_networks(networks)
        .with_allowed_suffixes(Vec::new())
        .with_loopback(true);
    let ten = format!("{}.0.0.1", 10_u8);
    let cases = [
        ("127.0.0.1", false, true),
        ("::1", false, true),
        ("::ffff:127.0.0.1", false, true),
        ("0.0.0.0", false, false),
        ("::", false, false),
        ("169.254.169.254", false, false),
        ("::ffff:169.254.169.254", false, false),
        ("fd00::1", true, true),
        (ten.as_str(), true, true),
        ("192.168.1.1", true, true),
        ("8.8.8.8", true, true),
    ];

    for (text, without_loopback, with_loopback) in cases {
        let address = text.parse::<IpAddr>()?;
        assert_eq!(
            admitted(&denied, "router.test", address).is_ok(),
            without_loopback,
            "network decision without loopback for {address}"
        );
        assert_eq!(
            admitted(&allowed, "router.test", address).is_ok(),
            with_loopback,
            "network decision with loopback for {address}"
        );
    }
    Ok(())
}
