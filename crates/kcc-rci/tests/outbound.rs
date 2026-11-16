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
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciError, RouterUrl, TlsMode, session::HttpTimeouts,
};
use kcc_testkit::outbound::lan_policy;

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

const fn embedded_forms(address: Ipv4Addr) -> [Ipv6Addr; 4] {
    let [first, second, third, fourth] = address.octets();
    let high = u16::from_be_bytes([first, second]);
    let low = u16::from_be_bytes([third, fourth]);
    [
        Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, high, low),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, high, low),
        Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, high, low),
        Ipv6Addr::new(0x2002, high, low, 0, 0, 0, 0, 1),
    ]
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
        ("3fff::1", false),
        ("3fff:0fff:ffff::1", false),
        ("3ff0::1", true),
        ("3fff:1000::1", true),
        ("5f00::1", false),
        ("5f00:ffff::1", false),
        ("5eff::1", true),
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
fn suffix_constructor_normalizes_domains_and_drops_empty_entries() -> TestResult {
    let policy = OutboundPolicy::default()
        .with_allowed_networks(Vec::new())
        .with_allowed_suffixes(vec![
            String::new(),
            " .LAN ".to_owned(),
            "keenetic.pro".to_owned(),
        ]);
    let public = "8.8.8.8".parse()?;

    assert!(admitted(&policy, "evil.com.", public).is_err());
    admitted(&policy, "router.lan", public)?;
    admitted(&policy, "ROUTER.KEENETIC.PRO", public)?;
    Ok(())
}

/// SEC2-06, A-13: the default policy admits no router address, loopback included.
#[test]
fn default_policy_refuses_every_address() -> TestResult {
    let policy = OutboundPolicy::default();
    let ten = format!("{}.0.0.1", 10_u8);
    let cases = [
        ("router.test", "127.0.0.1"),
        ("router.test", "::1"),
        ("router.test", ten.as_str()),
        ("router.test", "100.64.0.1"),
        ("router.test", "fd00::1"),
        ("router.test", "8.8.8.8"),
        ("router.keenetic.pro", "8.8.8.8"),
        ("router.netcraze.io", "8.8.8.8"),
    ];

    for (host, text) in cases {
        let address = text.parse::<IpAddr>()?;
        assert!(
            admitted(&policy, host, address).is_err(),
            "default policy admitted {host} at {address}"
        );
    }
    Ok(())
}

/// SEC2-10: a bracketed IPv6 literal origin is checked as an address instead of being
/// looked up as a name, so it passes when its network is admitted and fails when not.
#[tokio::test]
async fn bracketed_ipv6_literal_follows_the_policy() -> TestResult {
    let unique_local = "http://[fd00::1]".parse::<RouterUrl>()?;
    let loopback = "http://[::1]:8080".parse::<RouterUrl>()?;
    let timeouts = HttpTimeouts::default();
    let allowed = OutboundPolicy::default()
        .with_allowed_networks(vec![AllowedNetwork::new("fd00::".parse()?, 8)?])
        .with_loopback(true);
    let elsewhere = OutboundPolicy::default()
        .with_allowed_networks(vec![AllowedNetwork::new("198.51.100.0".parse()?, 24)?]);

    for router in [&unique_local, &loopback] {
        drop(
            allowed
                .client_builder(router, &TlsMode::Verify, timeouts)
                .await?,
        );
        let refused = elsewhere
            .client_builder(router, &TlsMode::Verify, timeouts)
            .await;
        assert!(
            matches!(refused, Err(RciError::Policy)),
            "{router} was admitted outside its network"
        );
    }
    Ok(())
}

/// SEC2-11: the link-local cloud credential, DNS and time endpoints stay refused even when
/// every network and loopback are admitted.
#[test]
fn link_local_cloud_endpoints_are_never_admitted() -> TestResult {
    let policy = OutboundPolicy::default()
        .with_allowed_networks(vec![
            AllowedNetwork::new("0.0.0.0".parse()?, 0)?,
            AllowedNetwork::new("::".parse()?, 0)?,
        ])
        .with_loopback(true);
    let cases = [
        "169.254.169.254",
        "169.254.169.253",
        "169.254.169.123",
        "169.254.170.2",
        "169.254.170.23",
        "fd00:ec2::254",
        "fd00:ec2::253",
        "fd00:ec2::23",
        "::ffff:169.254.170.2",
    ];

    for text in cases {
        let address = text.parse::<IpAddr>()?;
        assert!(
            admitted(&policy, "router.test", address).is_err(),
            "metadata endpoint {address} was admitted"
        );
    }
    admitted(&policy, "router.test", "169.254.1.1".parse()?)?;
    Ok(())
}

#[test]
fn lan_policy_applies_builtin_suffixes_only_to_global_addresses() -> TestResult {
    let policy = lan_policy();
    let suffix_only = lan_policy().with_allowed_networks(Vec::new());
    let public = Ipv4Addr::new(8, 8, 8, 8).into();
    let private = format!("{}.0.0.1", 10_u8).parse()?;

    admitted(&policy, "router.keenetic.pro", public)?;
    admitted(&policy, "keenetic.pro", public)?;
    assert!(admitted(&policy, "evilkeenetic.pro", public).is_err());
    assert!(admitted(&suffix_only, "router.keenetic.pro", private).is_err());
    admitted(&policy, "router.keenetic.pro", private)?;
    Ok(())
}

#[test]
fn network_path_canonicalizes_addresses_and_honors_loopback_separately() -> TestResult {
    let ten_network = format!("{}.0.0.0", 10_u8);
    let networks = vec![
        AllowedNetwork::new(ten_network.parse()?, 8)?,
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

#[test]
fn embedded_ipv4_policy_applies_on_suffix_and_outer_network_paths() -> TestResult {
    let suffix = OutboundPolicy::default()
        .with_allowed_networks(Vec::new())
        .with_allowed_suffixes(vec![".keenetic.pro".to_owned()]);
    let outer_networks = vec![
        AllowedNetwork::new("64:ff9b::".parse()?, 96)?,
        AllowedNetwork::new("::".parse()?, 96)?,
        AllowedNetwork::new("::ffff:0:0:0".parse()?, 96)?,
        AllowedNetwork::new("2002::".parse()?, 16)?,
    ];
    let network = OutboundPolicy::default()
        .with_allowed_networks(outer_networks.clone())
        .with_allowed_suffixes(Vec::new());
    let network_with_loopback = OutboundPolicy::default()
        .with_allowed_networks(outer_networks)
        .with_allowed_suffixes(Vec::new())
        .with_loopback(true);
    let private = format!("{}.0.0.1", 10_u8).parse::<Ipv4Addr>()?;
    let cases = [
        (Ipv4Addr::new(169, 254, 169, 254), false, false),
        (Ipv4Addr::LOCALHOST, false, true),
        (Ipv4Addr::UNSPECIFIED, false, false),
        (private, false, true),
        (Ipv4Addr::new(8, 8, 8, 8), true, true),
    ];

    for (embedded, suffix_expected, network_with_loopback_expected) in cases {
        for outer in embedded_forms(embedded) {
            let address = IpAddr::V6(outer);
            assert_eq!(
                admitted(&suffix, "router.keenetic.pro", address).is_ok(),
                suffix_expected,
                "suffix decision for {outer} embedding {embedded}"
            );
            assert_eq!(
                admitted(&network, "router.test", address).is_ok(),
                network_with_loopback_expected && !embedded.is_loopback(),
                "network decision without loopback for {outer} embedding {embedded}"
            );
            assert_eq!(
                admitted(&network_with_loopback, "router.test", address).is_ok(),
                network_with_loopback_expected,
                "network decision with loopback for {outer} embedding {embedded}"
            );
        }
    }
    Ok(())
}

#[test]
fn local_nat64_and_teredo_are_never_admitted() -> TestResult {
    let suffix = OutboundPolicy::default()
        .with_allowed_networks(Vec::new())
        .with_allowed_suffixes(vec![".keenetic.pro".to_owned()]);
    let network = OutboundPolicy::default()
        .with_allowed_networks(vec![AllowedNetwork::new("::".parse()?, 0)?])
        .with_allowed_suffixes(Vec::new())
        .with_loopback(true);

    for address_text in ["64:ff9b:1::1", "2001::1"] {
        let address = address_text.parse::<IpAddr>()?;
        assert!(
            admitted(&suffix, "router.keenetic.pro", address).is_err(),
            "suffix admitted {address}"
        );
        assert!(
            admitted(&network, "router.test", address).is_err(),
            "network admitted {address}"
        );
    }
    Ok(())
}
