//! Public HTTP checks for synthetic domain fixtures.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_config::config_text::{Token, flatten, parse};
    use kcc_rci::{
        OutboundPolicy, RciBody, RciClient, RciClientOptions, RciPath, RouterUrl, auth::Credentials,
    };
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
    use secrecy::SecretString;
    use serde_json::Value;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// Builds a spawned default router and authenticated client.
    async fn spawned() -> TestResult<(kcc_testkit::Handle, RciClient)> {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let router = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let client = RciClient::connect_with(router, credentials, options).await?;
        Ok((handle, client))
    }

    /// Every show-rc membership edge is represented by the running configuration text.
    // NOT cancel-safe: the fixture owns router tasks until shutdown.
    #[tokio::test]
    async fn bridge_membership_text_agrees_with_show_rc() -> TestResult {
        let (handle, client) = spawned().await?;
        let RciBody::Json(response) = client.show_rc(serde_json::json!({"interface":{}})).await?
        else {
            return Err("expected show rc JSON".into());
        };
        let interfaces = response
            .value
            .pointer("/show/rc/interface")
            .and_then(Value::as_object)
            .ok_or("interface tree")?;
        let text = handle.running_config_text();
        let ast = parse(&text)?;
        let lines = flatten(&ast);
        let mut count = 0_usize;
        for (bridge, fields) in interfaces {
            for keyword in ["include", "inherit"] {
                for member in fields
                    .get(keyword)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = member
                        .get("interface")
                        .and_then(Value::as_str)
                        .ok_or("member")?;
                    let expected = ["interface", bridge, keyword, name];
                    assert!(
                        lines.iter().any(|line| line
                            .tokens
                            .iter()
                            .filter_map(|token| match token {
                                Token::Word(word) => Some(word.as_str()),
                                Token::Ns3(_) | _ => None,
                            })
                            .eq(expected)),
                        "missing membership {expected:?}"
                    );
                    count = count.saturating_add(1);
                }
            }
        }
        assert_eq!(count, 5, "default bridge members");
        assert_eq!(handle.running_config_text(), handle.startup_config_text());
        handle.shutdown().await?;
        Ok(())
    }

    /// Reads one JSON show response.
    async fn show(client: &RciClient, segments: &[&str]) -> TestResult<Value> {
        let path = RciPath::from_segments(segments)?;
        match client.show(&path, &()).await? {
            RciBody::Json(response) => Ok(response.value),
            RciBody::Text(_) => Err("expected JSON show response".into()),
            _ => Err("unsupported show response".into()),
        }
    }

    /// Required domain fixtures expose complete wired and wireless client data.
    #[tokio::test]
    async fn client_fixtures_cover_wired_wireless_and_registration_states() -> TestResult {
        let (handle, client) = spawned().await?;

        let hotspot = show(&client, &["show", "ip", "hotspot"]).await?;
        let rows = hotspot.as_array().ok_or("hotspot array")?;
        assert_eq!(rows.len(), 6);
        assert!(
            rows.iter()
                .any(|row| row.get("interface") == Some(&Value::from("Bridge0")))
        );
        assert!(rows.iter().any(|row| row.get("rssi").is_some()));
        assert!(
            rows.iter()
                .any(|row| row.get("registered") == Some(&Value::Bool(true)))
        );
        assert!(
            rows.iter()
                .any(|row| row.get("registered") == Some(&Value::Bool(false)))
        );
        for path in [
            &["show", "ip", "dhcp", "bindings"][..],
            &["show", "ip", "arp"][..],
            &["show", "associations"][..],
        ] {
            assert!(
                !show(&client, path)
                    .await?
                    .as_array()
                    .is_none_or(Vec::is_empty)
            );
        }
        handle.shutdown().await?;
        Ok(())
    }

    /// Interfaces include management, WAN, both radios, access points, and numeric counters.
    #[tokio::test]
    async fn interface_fixtures_support_management_and_traffic_consumers() -> TestResult {
        let (handle, client) = spawned().await?;

        let interfaces = show(&client, &["show", "interface"]).await?;
        assert_eq!(
            interfaces.pointer("/Bridge0/address"),
            Some(&Value::from("192.0.2.1"))
        );
        assert_eq!(
            interfaces.pointer("/ISP/defaultgw"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            interfaces.pointer("/WifiMaster0/band"),
            Some(&Value::from("2.4"))
        );
        assert_eq!(
            interfaces.pointer("/WifiMaster1/band"),
            Some(&Value::from("5"))
        );
        assert!(interfaces.get("WifiMaster0/AccessPoint0").is_some());
        assert!(interfaces.get("WifiMaster1/AccessPoint0").is_some());
        let stats_path = RciPath::from_segments(["show", "interface", "stat"])?;
        let stats = match client.show(&stats_path, &[("name", "ISP")]).await? {
            RciBody::Json(response) => response.value,
            RciBody::Text(_) => return Err("expected JSON stats".into()),
            _ => return Err("unsupported stats response".into()),
        };
        assert!(stats.get("rxbytes").and_then(Value::as_u64).is_some());
        assert!(stats.get("txbytes").and_then(Value::as_u64).is_some());
        handle.shutdown().await?;
        Ok(())
    }

    /// NAT is deliberately large and every required supporting show family is present.
    #[tokio::test]
    async fn routing_and_service_fixtures_are_complete_and_large() -> TestResult {
        let (handle, client) = spawned().await?;

        let nat = show(&client, &["show", "ip", "nat"]).await?;
        assert_eq!(nat.as_array().map(Vec::len), Some(480));
        assert!(serde_json::to_vec(&nat)?.len() > 100_000);
        for path in [
            &["show", "ip", "policy"][..],
            &["show", "ip", "route"][..],
            &["show", "ipv6", "route"][..],
            &["show", "dns-proxy"][..],
            &["show", "media"][..],
            &["show", "usb"][..],
            &["show", "schedule"][..],
            &["show", "ndns"][..],
            &["show", "mws", "member"][..],
            &["show", "upnp", "redirect"][..],
        ] {
            let value = show(&client, path).await?;
            assert!(!value.is_null(), "{}", path.join("/"));
        }
        handle.shutdown().await?;
        Ok(())
    }

    /// Pinned optional capabilities remain absent despite fixture expansion.
    #[tokio::test]
    async fn bands_and_system_mode_remain_absent() -> TestResult {
        let (handle, client) = spawned().await?;

        for segments in [
            &["show", "interface", "bands"][..],
            &["show", "system", "mode"][..],
        ] {
            let path = RciPath::from_segments(segments)?;
            assert!(
                client.get(&path, &()).await.is_err(),
                "{}",
                segments.join("/")
            );
        }
        handle.shutdown().await?;
        Ok(())
    }
}
