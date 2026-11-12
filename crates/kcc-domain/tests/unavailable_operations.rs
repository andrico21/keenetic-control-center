//! Operations the 4.3.9 catalog view lacks are refused before any router request.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_catalog::ValidationIssue;
use kcc_domain::{
    DomainError, DomainId,
    dns::{self, DnsChange, DnsRoute},
    registry, services, system,
    vpn_clients::{self, VpnClientChange},
    vpn_servers::{self, VpnServerChange},
};
use kcc_testkit::model::Firmware;

use crate::support::{Fixture, PROFILES, TestResult};

/// Registry operations documented on 5.1 and absent from the KN-1811 4.3.9 catalog.
const ABSENT_ON_4_3: [(DomainId, &str, &str); 5] = [
    (DomainId::System, "system_mode", "show system mode"),
    (DomainId::Diagnostics, "iperf3", "tools iperf3"),
    (DomainId::Dns, "route", "dns-proxy route object-group"),
    (
        DomainId::VpnClients,
        "openconnect_protocol",
        "interface openconnect protocol",
    ),
    (
        DomainId::VpnServers,
        "wireguard_interface",
        "wireguard-server interface",
    ),
];

#[tokio::test]
async fn descriptors_offer_an_operation_only_where_the_catalog_documents_it() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let catalog = &fixture.context().catalog;
        for (domain, name, _path) in ABSENT_ON_4_3 {
            let descriptor = registry()
                .iter()
                .find(|candidate| candidate.id == domain)
                .ok_or("registry lacks the domain")?;
            let offered = descriptor
                .available_reads(catalog)
                .chain(descriptor.available_writes(catalog))
                .any(|operation| operation.name == name);
            assert_eq!(
                offered,
                firmware == Firmware::V5_1,
                "{firmware} {domain:?}/{name}"
            );
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn planners_refuse_operations_absent_from_4_3_without_a_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let router = fixture.context();
        let before = fixture.handle().request_count();
        let unavailable_vpn = vpn_clients::plan_change(
            router,
            &VpnClientChange::OpenConnectProtocol {
                name: "OpenConnect0".to_owned(),
                protocol: "anyconnect".to_owned(),
            },
        )
        .await
        .map(drop);
        let outcomes = [
            (
                "service iperf3",
                services::plan_service(router, "iperf3", true).map(drop),
            ),
            (
                "dns-proxy route object-group",
                dns::plan_change(router, &DnsChange::Route(DnsRoute::new("Blocked"))).map(drop),
            ),
            ("interface openconnect protocol", unavailable_vpn),
            (
                "wireguard-server interface",
                vpn_servers::plan_change(
                    router,
                    &VpnServerChange::WireGuardInterface {
                        interface: "Wireguard0".to_owned(),
                        enabled: true,
                    },
                )
                .map(drop),
            ),
        ];
        for (path, outcome) in outcomes {
            if firmware == Firmware::V4_3 {
                assert_unknown_path(&outcome, path);
            } else {
                assert!(outcome.is_ok(), "{firmware} {path}: {outcome:?}");
            }
        }
        if firmware == Firmware::V4_3 {
            assert_unknown_path(
                &system::read_system_mode(router).await.map(drop),
                "show system mode",
            );
        }
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "{firmware}: planning or refusing sends nothing"
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Asserts the typed catalog refusal naming `path`.
fn assert_unknown_path(outcome: &kcc_domain::Result<()>, path: &str) {
    assert!(
        matches!(
            outcome,
            Err(DomainError::Validation { issues })
                if issues.iter().any(|issue| matches!(
                    issue,
                    ValidationIssue::UnknownPath { path: refused } if refused == path
                ))
        ),
        "{path}: {outcome:?}"
    );
}
