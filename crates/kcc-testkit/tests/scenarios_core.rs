//! Client, segment, Wi-Fi, fail-safe, and user prerequisite scenarios.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::str::FromStr as _;

    use axum::http::Method;
    use kcc_rci::{ObjectName, RciPath};
    use kcc_testkit::{FaultInjection, model::Profile};
    use serde_json::{Value, json};

    use crate::support::{TestResult, json, spawned};

    /// Registration precedes deny, direct hotspot removal errors, and known-host removal cascades.
    #[tokio::test]
    async fn unregistered_client_block_and_cascade() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let mac = "02:00:00:00:00:99";
        drop(client.parse(&format!("known host blocked {mac}")).await?);
        drop(client.parse(&format!("ip hotspot host {mac} deny")).await?);
        let hotspot_path = RciPath::from_segments(["show", "ip", "hotspot"])?;
        let hotspot = json(client.show(&hotspot_path, &()).await?)?;
        assert!(
            hotspot
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| {
                    row.get("mac") == Some(&json!(mac))
                        && row.get("name") == Some(&json!("blocked"))
                        && row.get("registered") == Some(&json!(true))
                        && row.get("access") == Some(&json!("deny"))
                }))
        );
        let direct_removal = client.parse(&format!("no ip hotspot host {mac}")).await;
        assert!(matches!(
            direct_removal,
            Err(kcc_rci::RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _
            })
        ));
        drop(client.parse(&format!("no known host {mac}")).await?);
        let after = json(client.show(&hotspot_path, &()).await?)?;
        assert!(!after.to_string().contains(mac));
        handle.shutdown().await?;
        Ok(())
    }

    /// Segment create and reverse delete restore both independent stores exactly.
    #[tokio::test]
    async fn segment_round_trip_and_bridge_failure_rollback() -> TestResult {
        let commands = [
            "interface Vlan9 vlan-id 9",
            "interface Bridge9 ip address 192.0.2.129 255.255.255.192",
            "ip dhcp pool Pool9 range 192.0.2.130 192.0.2.180",
            "ip nat Bridge9",
            "ip policy Policy9 description segment",
        ];
        let rollback = [
            "no ip policy Policy9",
            "no ip nat Bridge9",
            "no ip dhcp pool Pool9",
            "no interface Bridge9",
            "no interface Vlan9",
        ];
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let settings = handle.settings_snapshot();
        let running = handle.running_config_text();
        for command in commands {
            drop(client.parse(command).await?);
        }
        for command in rollback {
            drop(client.parse(command).await?);
        }
        assert_eq!(handle.settings_snapshot(), settings);
        assert_eq!(handle.running_config_text(), running);
        handle.shutdown().await?;

        let faults = FaultInjection::default().fail_parse_matching("interface Bridge9", 1);
        let (failed_handle, failed_client) = spawned(Profile::default(), faults).await?;
        let failed_settings = failed_handle.settings_snapshot();
        let failed_running = failed_handle.running_config_text();
        drop(failed_client.parse(commands[0]).await?);
        let bridge_failure = failed_client.parse(commands[1]).await;
        assert!(matches!(
            bridge_failure,
            Err(kcc_rci::RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _
            })
        ));
        drop(failed_client.parse("no interface Vlan9").await?);
        assert_eq!(failed_handle.settings_snapshot(), failed_settings);
        assert_eq!(failed_handle.running_config_text(), failed_running);
        failed_handle.shutdown().await?;
        Ok(())
    }

    /// AP secret writes store NS3 and slash-name reads use POST without leaking plaintext.
    #[tokio::test]
    async fn access_point_secret_and_slash_name_read_are_safe() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let secret = "fixture-psk-plaintext";
        drop(
            client
                .parse("interface WifiMaster0/AccessPoint0 ssid changed")
                .await?,
        );
        drop(
            client
                .parse(&format!(
                    "interface WifiMaster0/AccessPoint0 authentication wpa-psk {secret}"
                ))
                .await?,
        );
        let name = ObjectName::from_str("WifiMaster0/AccessPoint0")?;
        let shown = json(client.show_interface(&name).await?)?;
        let serialized = shown.to_string();
        assert_eq!(
            shown.pointer("/show/interface/ssid"),
            Some(&json!("changed"))
        );
        assert!(!serialized.contains(secret));
        assert!(!handle.running_config_text().contains(secret));
        assert!(
            handle
                .running_config_text()
                .contains("authentication wpa-psk ns3")
        );
        let records = handle.request_log();
        assert!(
            records
                .iter()
                .any(|record| record.method() == Method::POST && record.path() == "/rci/")
        );
        assert!(
            !records
                .iter()
                .any(|record| record.path().contains("/AccessPoint0"))
        );
        assert!(!format!("{records:?}").contains(secret));
        handle.shutdown().await?;
        Ok(())
    }

    /// Fail-safe disarm preserves unsaved running state and unchanged startup text.
    #[tokio::test]
    async fn management_change_fail_safe_disarm_preserves_unsaved_state() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let startup = handle.startup_config_text();
        drop(client.parse("interface Bridge0 down").await?);
        drop(
            client
                .parse("system configuration fail-safe timer reboot 300")
                .await?,
        );
        let path = RciPath::from_segments(["show", "last-change"])?;
        let armed = json(client.show(&path, &()).await?)?;
        assert_eq!(armed.pointer("/fail-safe/active"), Some(&Value::Bool(true)));
        drop(
            client
                .parse("no system configuration fail-safe timer")
                .await?,
        );
        let disarmed = json(client.show(&path, &()).await?)?;
        assert_eq!(
            disarmed.pointer("/fail-safe/active"),
            Some(&Value::Bool(false))
        );
        assert_eq!(disarmed.get("unsaved"), Some(&Value::Bool(true)));
        assert_eq!(handle.startup_config_text(), startup);
        handle.shutdown().await?;
        Ok(())
    }

    /// User tags are projected and individual tag removal preserves hashed password material.
    #[tokio::test]
    async fn user_tags_mutate_without_plain_passwords() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let secret = "user-password-material";
        drop(
            client
                .parse(&format!("user operator password plain {secret}"))
                .await?,
        );
        drop(client.parse("user operator tag cli").await?);
        drop(client.parse("user operator tag readonly").await?);
        let shown = client.show_rc(json!({"user":{}})).await?;
        assert!(shown.configuration_tree().to_string().contains("readonly"));
        assert!(!shown.configuration_tree().to_string().contains(secret));
        drop(client.parse("no user operator tag cli").await?);
        let after = client.show_rc(json!({"user":{}})).await?;
        assert!(!after.configuration_tree().to_string().contains("\"cli\""));
        assert!(after.configuration_tree().to_string().contains("readonly"));
        handle.shutdown().await?;
        Ok(())
    }
}
