//! Regression coverage for generated argument types used by curated domains.

use core::str::FromStr as _;

use kcc_rci::version::FirmwareVersion;
use serde_json::{Value, json};

use crate::{Catalog, HttpMethod, ValidationIssue};

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn domain_command_bodies_use_realistic_generated_types() {
    let catalog = Catalog::for_firmware_and_model(
        FirmwareVersion::from_str("5.1.0").expect("test firmware is valid"),
        Some("KN-1811"),
    )
    .expect("generated catalog is valid");
    let cases = [network_cases(), interface_cases(), service_cases()].concat();
    for (path, valid, invalid) in cases {
        let result = catalog.validate(path, HttpMethod::Post, &valid);
        assert!(
            result.is_ok(),
            "{path} rejected valid body {valid}: {result:?}"
        );
        let issues = catalog
            .validate(path, HttpMethod::Post, &invalid)
            .expect_err("invalid body must be rejected");
        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                ValidationIssue::InvalidValue { field: _ }
                    | ValidationIssue::UnknownField {
                        field: _,
                        suggestion: _
                    }
                    | ValidationIssue::NoPrefixUnsupported
            )),
            "{path} produced no value/field issue for {invalid}: {issues:?}"
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn any_address_and_zero_mask_are_valid_without_loosening_mask_checks() {
    let catalog = Catalog::for_firmware_and_model(
        FirmwareVersion::from_str("5.1.0").expect("test firmware is valid"),
        Some("KN-1811"),
    )
    .expect("generated catalog is valid");
    for path in ["access-list permit", "access-list deny"] {
        let valid = json!({
            "source":"0.0.0.0",
            "source-mask":"0.0.0.0",
            "destination":"0.0.0.0",
            "destination-mask":"0.0.0.0"
        });
        assert!(
            catalog.validate(path, HttpMethod::Post, &valid).is_ok(),
            "{path}"
        );
        for mask in ["255.0.255.0", "0.0.0.1"] {
            let invalid = json!({"source":"0.0.0.0","source-mask":mask});
            assert!(
                catalog.validate(path, HttpMethod::Post, &invalid).is_err(),
                "{path} {mask}"
            );
        }
    }
    for prefix in ["0.0.0.0/0", "0.0.0.0/32"] {
        assert!(
            catalog
                .validate(
                    "ipv6 route",
                    HttpMethod::Post,
                    &json!({"prefix":prefix,"gateway":"192.0.2.1"})
                )
                .is_ok(),
            "{prefix}"
        );
    }
}

type Case = (&'static str, Value, Value);

/// Builds routing, policy, host, DHCP, and access-list validation cases.
fn network_cases() -> Vec<Case> {
    vec![
        (
            "ip route",
            json!({"network":"198.51.100.0","mask":"255.255.255.0","gateway":"192.0.2.254"}),
            json!({"gateway":"not-an-address"}),
        ),
        (
            "ipv6 route",
            json!({"prefix":"2001:db8::/64","gateway":"2001:db8::1"}),
            json!({"prefix":"2001:db8::/129"}),
        ),
        (
            "ip static",
            json!({"protocol":"tcp","address":"192.0.2.10","port":443_i32,"to-address":"198.51.100.10","to-port":8_443_i32}),
            json!({"protocol":"smtp"}),
        ),
        (
            "ip nat",
            json!({"interface":"ISP"}),
            json!({"address":"bad-address"}),
        ),
        (
            "access-list permit",
            json!({"source":"10.0.0.0","source-mask":"255.255.255.0","destination":"192.0.2.10","destination-mask":"255.255.255.255"}),
            json!({"source-mask":"255.0.255.0"}),
        ),
        (
            "access-list rule",
            json!({"index":10_i32,"description":"allow web"}),
            json!({"index":"ten"}),
        ),
        (
            "access-list rule",
            json!({"index":10_i32,"new-index":2_i32}),
            json!({"index":10_i32,"new-index":"first"}),
        ),
        (
            "ip policy",
            json!({"name":"Policy0"}),
            json!({"name":"bad name"}),
        ),
        (
            "ip policy route",
            json!({"network":"203.0.113.0","mask":"255.255.255.0","interface":"Wireguard0"}),
            json!({"mask":"255.0.255.0"}),
        ),
        (
            "ip hotspot host",
            json!({"mac":"02:00:00:00:00:01","policy":"Policy0","schedule":"WorkHours"}),
            json!({"mac":"invalid"}),
        ),
        (
            "known host",
            json!({"name":"printer","mac":"02:00:00:00:00:02"}),
            json!({"mac":"invalid"}),
        ),
        (
            "ip dhcp host",
            json!({"host":"printer"}),
            json!({"host":false}),
        ),
        (
            "ip dhcp pool",
            json!({"name":"Home"}),
            json!({"name":42_i32}),
        ),
    ]
}

/// Builds interface, DNS, host-object, and WireGuard validation cases.
fn interface_cases() -> Vec<Case> {
    vec![
        (
            "interface ip address",
            json!({"address":"192.0.2.1","mask":"255.255.255.0"}),
            json!({"mask":"255.0.255.0"}),
        ),
        (
            "interface ip global",
            json!({"priority":100_i32}),
            json!({"priority":"high"}),
        ),
        (
            "interface ssid",
            json!({"ssid":"Guest Wi-Fi"}),
            json!({"ssid":false}),
        ),
        (
            "interface authentication wpa-psk",
            json!({"psk":"correct horse battery staple"}),
            json!({"psk":false}),
        ),
        (
            "interface security-level",
            json!({"private":true}),
            json!({"private":"yes"}),
        ),
        ("interface up", json!({}), json!({"enabled":true})),
        (
            "dns-proxy tls upstream",
            json!({"address":"1.1.1.1","port":853_i32,"fqdn":"cloudflare-dns.com"}),
            json!({"address":"invalid"}),
        ),
        (
            "dns-proxy https upstream",
            json!({"url":"https://dns.example/dns-query","format":"json","interface":"ISP"}),
            json!({"format":"xml"}),
        ),
        (
            "ip host",
            json!({"domain":"router.example","address":"192.0.2.20"}),
            json!({"address":"invalid"}),
        ),
        (
            "object-group fqdn",
            json!({"name":"TrustedSites"}),
            json!({"name":false}),
        ),
        (
            "interface wireguard private-key",
            json!({"private-key":"base64-private-key"}),
            json!({"private-key":false}),
        ),
        (
            "interface wireguard listen-port",
            json!({"port":51_820_i32}),
            json!({"port":"51820"}),
        ),
        (
            "interface wireguard peer",
            json!({"key":"base64-public-key"}),
            json!({"key":false}),
        ),
        (
            "interface wireguard peer allow-ips",
            json!({"address":"198.51.100.0","mask":"255.255.0.0"}),
            json!({"mask":"255.0.255.0"}),
        ),
        (
            "interface wireguard peer endpoint",
            json!({"address":"198.51.100.10","port":51_820_i32}),
            json!({"port":"51820"}),
        ),
    ]
}

/// Builds user, service, schedule, NDNS, logging, and component validation cases.
fn service_cases() -> Vec<Case> {
    vec![
        (
            "user tag",
            json!({"tag":"manager"}),
            json!({"tag":"administrator"}),
        ),
        (
            "user password plain",
            json!({"password":"new-password"}),
            json!({"password":false}),
        ),
        ("service http", json!({}), json!({"enabled":true})),
        (
            "ip http port",
            json!({"port":8_080_i32}),
            json!({"port":"8080"}),
        ),
        (
            "ip ssh port",
            json!({"number":2_222_i32}),
            json!({"number":"2222"}),
        ),
        (
            "ip telnet port",
            json!({"number":2_323_i32}),
            json!({"number":"2323"}),
        ),
        (
            "schedule description",
            json!({"description":"Weekday access"}),
            json!({"description":false}),
        ),
        (
            "ndns book-name",
            json!({"name":"my-router","domain":"example.keenetic.pro","access":"cloud"}),
            json!({"access":"public"}),
        ),
        (
            "system log server",
            json!({"address":"192.0.2.50","port":514_i32}),
            json!({"address":"logger.example"}),
        ),
        (
            "components preset",
            json!({"preset":"minimal"}),
            json!({"preset":"everything"}),
        ),
        ("interface up", json!({"no":true}), json!({"no":false})),
    ]
}
