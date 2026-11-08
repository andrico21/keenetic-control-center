//! VPN server writes reject acknowledged parser no-ops.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration tests report failures through assertions"
)]
mod tests {
    use kcc_app::workflow::WorkflowError;
    use kcc_domain::vpn_servers::{self, VpnServerChange, VpnServerService};
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, TestResult};

    /// VPN service activation must be visible after a successful parser reply.
    #[tokio::test]
    async fn silent_vpn_service_names_failed_field() -> TestResult {
        let fixture =
            Fixture::spawn_with_faults(FaultInjection::default().silent_noop_path("parse")).await?;
        let operation = vpn_servers::plan_change(
            fixture.context(),
            &VpnServerChange::Service {
                service: VpnServerService::Sstp,
                enabled: true,
            },
        )?;
        let mut changes = fixture.changes().await?;
        let outcome = changes
            .apply_cli(vpn_servers::change_request(&operation)?)
            .await;
        assert!(
            matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("service")),
            "ignored VPN service must fail verification: {outcome:?}"
        );
        drop(changes);
        fixture.shutdown().await
    }

    /// VPN server service, binding and pool settings verify against mutable state.
    #[tokio::test]
    async fn vpn_server_settings_are_read_back() -> TestResult {
        let fixture = Fixture::spawn().await?;
        for change in [
            VpnServerChange::Service {
                service: VpnServerService::Sstp,
                enabled: true,
            },
            VpnServerChange::SstpInterface {
                interface: "Bridge0".to_owned(),
            },
            VpnServerChange::SstpPool {
                begin: "192.0.2.67".to_owned(),
                size: Some(5),
            },
        ] {
            let operation = vpn_servers::plan_change(fixture.context(), &change)?;
            let mut changes = fixture.changes().await?;
            assert!(
                changes
                    .apply_cli(vpn_servers::change_request(&operation)?)
                    .await?
                    .unsaved
            );
        }
        fixture.shutdown().await
    }

    /// Named IPsec maps verify their own virtual-IP fields.
    #[tokio::test]
    async fn crypto_map_settings_are_read_back() -> TestResult {
        let fixture = Fixture::spawn().await?;
        for change in [
            VpnServerChange::IpsecMap {
                name: "map67".to_owned(),
            },
            VpnServerChange::IpsecVirtualIp {
                name: "map67".to_owned(),
                enabled: true,
            },
            VpnServerChange::IpsecVirtualIpPool {
                name: "map67".to_owned(),
                begin: "192.0.2.67".to_owned(),
                end: None,
                size: Some(5),
            },
            VpnServerChange::IpsecVirtualIpDns {
                name: "map67".to_owned(),
                primary: "192.0.2.1".to_owned(),
                secondary: None,
            },
        ] {
            let operation = vpn_servers::plan_change(fixture.context(), &change)?;
            let mut changes = fixture.changes().await?;
            assert!(
                changes
                    .apply_cli(vpn_servers::change_request(&operation)?)
                    .await?
                    .unsaved
            );
        }
        fixture.shutdown().await
    }
}
