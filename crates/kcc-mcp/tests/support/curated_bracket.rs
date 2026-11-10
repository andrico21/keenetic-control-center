//! Every curated management operation carries recovery on both router modes.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish management recovery"
)]
mod tests {
    use std::io::{self, Write as _};

    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Runs one real write on both recovery mechanisms and checks the wire bracket.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    async fn bracket(tool: &str, input: Value) -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let fake = FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario);
            let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
            if input.get("op").and_then(Value::as_str) == Some("address_dhcp") {
                let cleared = lab.call("kcc_rci_delete", json!({"host":"lab-1", "catalog_path":"interface", "path":["interface"], "value":{"name":"Bridge0"}, "confirm":true}), false).await?;
                assert_eq!(cleared.error(), None, "clear static fixture: {cleared:?}");
                for line in ["no interface Bridge0", "interface Bridge0"] {
                    let prepared = lab
                        .call(
                            "kcc_cli_parse",
                            json!({"host":"lab-1", "line":line, "confirm":true}),
                            false,
                        )
                        .await?;
                    assert_eq!(
                        prepared.error(),
                        None,
                        "management interface setup: {prepared:?}"
                    );
                }
            }
            let before = lab.router("lab-1")?.request_log().len();
            let reply = lab.call(tool, input.clone(), false).await?;
            let commands = lab
                .router("lab-1")?
                .request_log()
                .iter()
                .skip(before)
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            let (arm, disarm) = if mode == "router" {
                (
                    "system configuration fail-safe timer reboot 300",
                    "no system configuration fail-safe timer",
                )
            } else {
                ("system reboot 300", "no system reboot")
            };
            assert!(
                commands.first().is_some_and(|line| line == arm),
                "{tool} {mode} must arm first: {commands:?}; {reply:?}"
            );
            assert!(
                commands.last().is_some_and(|line| line == disarm),
                "{tool} {mode} must disarm last: {commands:?}; {reply:?}"
            );
            assert_eq!(reply.error(), None, "{tool} {mode}: {reply:?}");
            writeln!(
                io::stderr(),
                "BRACKET MCP admin {mode} {tool} {}: arm + disarm",
                input.get("op").ok_or("operation")?
            )?;
            lab.stop().await?;
        }
        Ok(())
    }

    /// Management listener ports are protected.
    #[tokio::test]
    async fn curated_bracket_management_port() -> TestResult {
        bracket("kcc_services_write", json!({"host":"lab-1","op":"management_port","name":"http","port":8082_u16,"confirm":true})).await
    }
    /// Management listener exposure is protected.
    #[tokio::test]
    async fn curated_bracket_management_security_level() -> TestResult {
        bracket("kcc_services_write", json!({"host":"lab-1","op":"management_security_level","name":"http","value":"private","confirm":true})).await
    }
    /// HTTPS settings are protected.
    #[tokio::test]
    async fn curated_bracket_http_ssl() -> TestResult {
        bracket(
            "kcc_services_write",
            json!({"host":"lab-1","op":"http_ssl","value":"enable","enabled":true,"confirm":true}),
        )
        .await
    }
    /// Remote HTTP proxies are protected.
    #[tokio::test]
    async fn curated_bracket_proxy() -> TestResult {
        bracket(
            "kcc_keendns_write",
            json!({"host":"lab-1","op":"proxy","name":"labproxy","enabled":true,"confirm":true}),
        )
        .await
    }
    /// Proxy upstream changes are protected.
    #[tokio::test]
    async fn curated_bracket_proxy_upstream() -> TestResult {
        bracket("kcc_keendns_write", json!({"host":"lab-1","op":"proxy_upstream","name":"labproxy","value":"http","target":"192.0.2.10","port":8080_u16,"confirm":true})).await
    }
    /// Cloud exposure changes are protected.
    #[tokio::test]
    async fn curated_bracket_cloud_security_level() -> TestResult {
        bracket(
            "kcc_keendns_write",
            json!({"host":"lab-1","op":"cloud_security_level","value":"private","confirm":true}),
        )
        .await
    }
    /// Router user creation is protected.
    #[tokio::test]
    async fn curated_bracket_user_create() -> TestResult {
        bracket(
            "kcc_router_users_write",
            json!({"host":"lab-1","op":"create","name":"bracket-user","confirm":true}),
        )
        .await
    }
    /// Router user deletion is protected.
    #[tokio::test]
    async fn curated_bracket_user_delete() -> TestResult {
        bracket(
            "kcc_router_users_write",
            json!({"host":"lab-1","op":"delete","name":"bracket-user","confirm":true}),
        )
        .await
    }
    /// Router access tags are protected.
    #[tokio::test]
    async fn curated_bracket_user_tag() -> TestResult {
        bracket("kcc_router_users_write", json!({"host":"lab-1","op":"set_tag","name":"bracket-user","value":"http","enabled":true,"confirm":true})).await
    }
    /// Router passwords are protected without exposing their value in evidence.
    #[tokio::test]
    async fn curated_bracket_user_password() -> TestResult {
        let secret = ["bracket", "fixture", "credential"].join("-");
        bracket("kcc_router_users_write", json!({"host":"lab-1","op":"set_password","name":"bracket-user","secret":secret,"confirm":true})).await
    }
    /// VPN account password changes also use the management bracket.
    #[tokio::test]
    async fn curated_bracket_vpn_password() -> TestResult {
        let secret = ["vpn", "fixture", "credential"].join("-");
        bracket("kcc_vpn_servers_write", json!({"host":"lab-1","op":"password","name":"bracket-user","secret":secret,"confirm":true})).await
    }
    /// Runtime management classification overrides ordinary WAN metadata.
    #[tokio::test]
    async fn curated_bracket_wan_static() -> TestResult {
        bracket("kcc_wan_write", json!({"host":"lab-1","op":"address_static","name":"Bridge0","value":"192.0.2.1","mask":"255.255.255.0","confirm":true})).await
    }
    /// DHCP addressing of the management bridge is also protected.
    #[tokio::test]
    async fn curated_bracket_wan_dhcp() -> TestResult {
        bracket(
            "kcc_wan_write",
            json!({"host":"lab-1","op":"address_dhcp","name":"Bridge0","confirm":true}),
        )
        .await
    }
    /// A role missing recovery permission is refused before router discovery.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn curated_bracket_missing_permission_sends_nothing() -> TestResult {
        let role = Role::new(
            "writer".to_owned(),
            [Permission::Read, Permission::Write],
            vec!["*".to_owned()],
        );
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            role,
        )
        .await?;
        let before = lab.requests("lab-1")?;
        let reply = lab.call("kcc_services_write", json!({"host":"lab-1","op":"management_port","name":"http","port":8082_u16,"confirm":true}), false).await?;
        assert_eq!(reply.error(), Some("forbidden"));
        assert_eq!(lab.requests("lab-1")?, before);
        lab.stop().await
    }
}
