//! Raw router output redaction through the MCP session boundary.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the raw MCP secret boundary"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// Dummy secrets built at run time: a PPPoE `ns3` blob, a plaintext Wi-Fi PSK and an
    /// IKE `ns3` blob.
    fn dummies() -> [String; 3] {
        [("Pp", 1_u8), ("Ww", 2), ("Ii", 3)]
            .map(|(pair, index)| format!("{}{index}", pair.repeat(15)))
    }

    /// A router whose `show running-config` lines and `show interface` answer hold the
    /// `secrets`, and the configuration lines it answers.
    fn configured(secrets: &[String; 3]) -> TestResult<(FakeRouter, Vec<String>)> {
        let [ppp, psk, ike] = secrets;
        let lines = vec![
            "interface PPPoE0".to_owned(),
            format!("    authentication password ns3 {ppp}"),
            "interface WifiMaster0/AccessPoint0".to_owned(),
            format!("    authentication wpa-psk {psk}"),
            format!("crypto ike key office ns3 {ike} any"),
        ];
        let router = FakeRouter::builder(Profile::default())
            .show_fixture("running-config", json!({ "message": lines }))
            .show_fixture(
                "interface",
                json!({"PPPoE0": {"id": "PPPoE0", "type": "PPPoE",
                    "authentication": {"password": {"ns3": ppp}}}}),
            )
            .build()?;
        Ok((router, lines))
    }

    /// The reply of `kcc_rci_read` for `show <command>` on `lab-1`.
    async fn read(lab: &Lab, command: &str) -> TestResult<Value> {
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({"host": "lab-1", "catalog_path": format!("show {command}"),
                    "path": ["show", command]}),
                false,
            )
            .await?;
        Ok(reply.value()?.clone())
    }

    /// SEC1-01, E-01: a role without `RevealSecrets` reads `show running-config` and
    /// `show interface` with every secret redacted.
    ///
    /// The configuration lines and the nested `{"password": {"ns3": ..}}` member both
    /// show `<redacted>`, and no secret appears anywhere in the reply.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn read_role_gets_configuration_secrets_redacted() -> TestResult {
        let secrets = dummies();
        let (router, _lines) = configured(&secrets)?;
        let viewer = Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        );
        let lab = Lab::start(vec![("lab-1", router)], viewer).await?;
        let config = read(&lab, "running-config").await?;
        assert_eq!(
            config.pointer("/value/message/1"),
            Some(&json!("    authentication password <redacted>")),
            "{config}"
        );
        assert_eq!(
            config.pointer("/value/message/3"),
            Some(&json!("    authentication wpa-psk <redacted>")),
            "{config}"
        );
        let interface = read(&lab, "interface").await?;
        assert_eq!(
            interface.pointer("/value/PPPoE0/authentication/password"),
            Some(&json!("<redacted>")),
            "{interface}"
        );
        for reply in [&config, &interface] {
            let text = reply.to_string();
            for secret in &secrets {
                assert!(!text.contains(secret.as_str()), "{secret} leaks: {text}");
            }
        }
        lab.stop().await
    }

    /// SEC1-01: a role holding `RevealSecrets` on the router reads the configuration lines
    /// as the router sent them.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn reveal_role_gets_configuration_lines_unchanged() -> TestResult {
        let secrets = dummies();
        let (router, lines) = configured(&secrets)?;
        let lab = Lab::start(vec![("lab-1", router)], admin()).await?;
        let config = read(&lab, "running-config").await?;
        assert_eq!(
            config.pointer("/value/message"),
            Some(&json!(lines)),
            "{config}"
        );
        lab.stop().await
    }

    /// Raw interface output masks secret fields even when the caller can write them.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn raw_interface_read_redacts_planted_secret() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let secret = ["dummy", "runtime", "wifi", "credential"].join("-");
        let planted = lab
            .call(
                "kcc_wifi_write",
                json!({
                    "host":"lab-1", "op":"wpa_psk", "name":"WifiMaster0/AccessPoint0",
                    "secret":secret
                }),
                false,
            )
            .await?;
        assert_eq!(planted.value()?.get("applied"), Some(&json!(true)));
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({
                    "host":"lab-1", "catalog_path":"show interface", "path":["show","interface"]
                }),
                false,
            )
            .await?;
        let value = reply.value()?;
        assert_eq!(
            value.pointer("/value/WifiMaster0~1AccessPoint0/authentication/wpa-psk"),
            Some(&json!("<redacted>"))
        );
        assert!(
            !value.to_string().contains(&secret),
            "secret never reaches MCP output"
        );
        lab.stop().await
    }

    /// SEC1-04: a raw read masks the hyphenated and short secret keys the Web masks.
    ///
    /// `private-key`, `obfs-key`, `preshare-key` and `community` are masked for a role
    /// that cannot reveal secrets.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn raw_read_masks_hyphenated_and_short_secret_keys() -> TestResult {
        let [private, obfuscation, preshared, community] =
            ["private", "obfs", "preshare", "community"].map(|kind| format!("dummy-{kind}-value"));
        let router = FakeRouter::builder(Profile::default())
            .show_fixture(
                "interface",
                json!({"Wireguard7": {
                    "id": "Wireguard7", "type": "Wireguard",
                    "wireguard": {
                        "private-key": private, "obfs-key": obfuscation,
                        "peer": [{"preshare-key": preshared}]
                    },
                    "snmp": {"community": community}
                }}),
            )
            .build()?;
        let viewer = Role::new(
            "viewer".to_owned(),
            [Permission::Read, Permission::RawRci],
            vec!["*".to_owned()],
        );
        let lab = Lab::start(vec![("lab-1", router)], viewer).await?;
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({
                    "host":"lab-1", "catalog_path":"show interface", "path":["show","interface"]
                }),
                false,
            )
            .await?;
        let value = reply.value()?;
        for pointer in [
            "/value/Wireguard7/wireguard/private-key",
            "/value/Wireguard7/wireguard/obfs-key",
            "/value/Wireguard7/wireguard/peer/0/preshare-key",
            "/value/Wireguard7/snmp/community",
        ] {
            assert_eq!(
                value.pointer(pointer),
                Some(&json!("<redacted>")),
                "{pointer}"
            );
        }
        for secret in [&private, &obfuscation, &preshared, &community] {
            assert!(!value.to_string().contains(secret.as_str()), "{secret}");
        }
        lab.stop().await
    }
}
