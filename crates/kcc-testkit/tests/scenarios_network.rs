//! Routing, DNS, WireGuard, and firmware-profile prerequisite scenarios.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_rci::{ObjectName, RciPath};
    use kcc_testkit::{
        FaultInjection,
        model::{Firmware, Model, Profile},
    };
    use serde_json::json;

    use crate::support::{TestResult, json, spawned};

    /// Routes change by one, route wipe is visible, static forwards project, and NAT is large.
    #[tokio::test]
    async fn routes_static_and_nat_support_safety_checks() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let route_path = RciPath::from_segments(["show", "ip", "route"])?;
        let before = json(client.show(&route_path, &()).await?)?
            .as_array()
            .map(Vec::len)
            .ok_or("route array")?;
        let route = "ip route 198.51.100.0 255.255.255.0 192.0.2.254";
        drop(client.parse(route).await?);
        let added = json(client.show(&route_path, &()).await?)?
            .as_array()
            .map(Vec::len)
            .ok_or("route array")?;
        assert_eq!(added, before.saturating_add(1));
        drop(client.parse(&format!("no {route}")).await?);
        let removed = json(client.show(&route_path, &()).await?)?
            .as_array()
            .map(Vec::len)
            .ok_or("route array")?;
        assert_eq!(removed, before);
        drop(
            client
                .parse("ip static tcp ISP 443 192.0.2.44 8443")
                .await?,
        );
        let forwards = client.show_rc(json!({"ip":{"static":{}}})).await?;
        assert!(forwards.configuration_tree().to_string().contains("8443"));
        let nat_path = RciPath::from_segments(["show", "ip", "nat"])?;
        assert_eq!(
            json(client.show(&nat_path, &()).await?)?
                .as_array()
                .map(Vec::len),
            Some(480)
        );
        handle.shutdown().await?;

        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let (wipe_handle, wipe_client) = spawned(Profile::default(), faults).await?;
        drop(wipe_client.parse(route).await?);
        let answer = json(
            wipe_client
                .post_root(&json!({"parse":format!("no {route}")}))
                .await?,
        )?;
        assert_eq!(
            answer.pointer("/status/0/message"),
            Some(&json!("cleared all routes."))
        );
        wipe_handle.shutdown().await?;
        Ok(())
    }

    /// Encrypted DNS and router-generated WireGuard expose operation but never key material.
    #[tokio::test]
    async fn dns_and_router_generated_wireguard_are_secret_safe() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        drop(
            client
                .parse("dns-proxy tls upstream 192.0.2.53 853 sni dns.fixture.invalid")
                .await?,
        );
        drop(
            client
                .parse("dns-proxy https upstream https://dns.fixture.invalid/dns-query")
                .await?,
        );
        drop(client.parse("interface Wireguard7").await?);
        drop(
            client
                .parse("interface Wireguard7 wireguard private-key")
                .await?,
        );
        drop(
            client
                .parse("interface Wireguard7 wireguard listen-port 51820")
                .await?,
        );
        drop(
            client
                .parse("interface Wireguard7 wireguard peer peer-public")
                .await?,
        );
        drop(
            client
                .parse(
                    "interface Wireguard7 wireguard peer peer-public endpoint 198.51.100.7 51820",
                )
                .await?,
        );
        drop(client.parse("interface Wireguard7 wireguard peer peer-public allow-ips 192.0.2.0 255.255.255.0").await?);
        drop(
            client
                .parse("interface Wireguard7 wireguard peer peer-public keepalive-interval 25")
                .await?,
        );
        let dns_path = RciPath::from_segments(["show", "dns-proxy"])?;
        let dns = json(client.show(&dns_path, &()).await?)?;
        assert!(dns.to_string().contains("dns.fixture.invalid"));
        let name = ObjectName::try_from("Wireguard7".to_owned())?;
        let interface = json(client.show_interface(&name).await?)?;
        let serialized = interface.to_string();
        assert_eq!(
            interface.pointer("/show/interface/type"),
            Some(&json!("Wireguard"))
        );
        assert!(serialized.contains("peer-public"));
        assert!(serialized.contains("keepalive-interval"));
        assert!(!serialized.contains("private-key-material"));
        assert!(!serialized.contains("preshared-key-material"));
        assert!(
            !handle
                .running_config_text()
                .contains("private-key-material")
        );
        handle.shutdown().await?;
        Ok(())
    }

    /// The documentation-derived 4.3 profile keeps IPv6 access lists absent.
    #[tokio::test]
    async fn ipv6_access_list_is_absent_on_4_3() -> TestResult {
        let profile = Profile::new(Model::Kn1811, Firmware::V4_3)?;
        let (handle, client) = spawned(profile, FaultInjection::default()).await?;
        let path = RciPath::from_segments(["ipv6", "access-list"])?;
        let missing = client.get(&path, &()).await;
        assert!(matches!(missing, Err(kcc_rci::RciError::NotFound)));
        handle.shutdown().await?;
        Ok(())
    }
}
