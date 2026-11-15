//! WireGuard import secret-boundary regression coverage.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the secret-boundary contract"
)]
mod tests {
    use std::process;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use kcc_app::audit::AUDIT_FILE_NAME;
    use kcc_domain::{DomainError, vpn_clients};
    use kcc_testkit::model::Firmware;
    use secrecy::SecretString;
    use tokio::fs;

    use crate::support::{Fixture, PROFILES, TestResult, TraceCapture, refused_by_catalog};

    /// Imported keys are stored without becoming observable in plans, reads, or logs.
    // NOT cancel-safe: applies writes to an isolated fake router.
    #[tokio::test]
    async fn imported_keys_are_protected_end_to_end() -> TestResult {
        for firmware in PROFILES {
            let trace = TraceCapture::install();
            let fixture = Fixture::spawn(firmware).await?;
            let private = STANDARD.encode([41_u8; 32]);
            let preshared = STANDARD.encode([42_u8; 32]);
            let public = STANDARD.encode([43_u8; 32]);
            let obfuscation = "interface-obfuscation";
            let peer_obfuscation = "peer-obfuscation";
            let obfuscated = format!(
                "[Interface]\nPrivateKey = {private}\nObfsKey = {obfuscation}\n[Peer]\nPublicKey = {public}\nPresharedKey = {preshared}\nObfsKey = {peer_obfuscation}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 192.0.2.0/24\nPersistentKeepalive = 25\n"
            );
            let (text, obfuscation_lines) = if firmware == Firmware::V4_3 {
                // 4.3.9 documents no WireGuard obfuscation keys: refused while planning.
                let sent = fixture.handle().request_count();
                let refused = vpn_clients::plan_wireguard_import(
                    fixture.context(),
                    "Wireguard7",
                    &vpn_clients::parse_wireguard_config(&obfuscated)?,
                )
                .await;
                assert!(refused_by_catalog(&refused), "obfuscation key accepted");
                assert_eq!(fixture.handle().request_count(), sent);
                let plain = obfuscated
                    .lines()
                    .filter(|line| !line.starts_with("ObfsKey"))
                    .flat_map(|line| [line, "\n"])
                    .collect::<String>();
                (plain, 0)
            } else {
                (obfuscated, 2)
            };
            let config = vpn_clients::parse_wireguard_config(&text)?;
            let operation =
                vpn_clients::plan_wireguard_import(fixture.context(), "Wireguard7", &config)
                    .await?;
            let request = vpn_clients::change_request(&operation)?;
            let printable = format!("{config:?} {operation:?} {request:?}");
            let mut changes = fixture.changes().await?;

            let result = changes.apply_cli(request).await?;

            let clients = vpn_clients::read_clients(fixture.context()).await?;
            let status = clients
                .iter()
                .find(|client| client.id == "Wireguard7")
                .and_then(|client| client.wireguard.as_ref())
                .ok_or("missing WireGuard status")?;
            assert!(
                status
                    .private_key_present
                    .is_some_and(|presence| presence.present)
            );
            let peer = status.peers.get(&public).ok_or("missing peer")?;
            assert!(
                peer.preshared_key_present
                    .is_some_and(|presence| presence.present)
            );
            assert_eq!(
                peer.endpoint.as_deref(),
                Some(["198.51.100.7".to_owned(), "51820".to_owned()].as_slice())
            );
            let stored = fixture.handle().running_config_text();
            assert!(stored.contains("wireguard private-key ns3"));
            assert!(stored.contains("preshared-key ns3"));
            assert_eq!(stored.matches("obfs-key ns3").count(), obfuscation_lines);
            let audit =
                String::from_utf8(fs::read(fixture.state_dir().join(AUDIT_FILE_NAME)).await?)?;
            for output in [
                printable,
                format!("{result:?} {clients:?}"),
                serde_json::to_string(&clients)?,
                stored,
                format!("{:?}", fixture.handle().request_log()),
                audit,
                trace.text()?,
            ] {
                for secret in [
                    private.as_str(),
                    preshared.as_str(),
                    obfuscation,
                    peer_obfuscation,
                ] {
                    assert!(
                        !output.contains(secret),
                        "secret escaped its protected boundary"
                    );
                }
            }
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Controls in imported secret fields fail during planning before router access.
    // NOT cancel-safe: creates an isolated fixture.
    #[tokio::test]
    async fn imported_key_controls_are_rejected_before_requests() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let public = STANDARD.encode([43_u8; 32]);
            let mut config = vpn_clients::parse_wireguard_config(&format!(
                "[Interface]\n[Peer]\nPublicKey = {public}\n"
            ))?;
            let before = fixture.handle().request_count();
            let head = format!("key-head-{}", process::id());
            let tail = format!("key-tail-{}", process::id());
            let key = format!("{head}\n{tail}");
            for field in ["private", "interface-obfs", "peer-obfs"] {
                config.interface.private_key = None;
                config.interface.obfuscation_key = None;
                let peer = config.peers.first_mut().ok_or("missing peer")?;
                peer.obfuscation_key = None;
                match field {
                    "private" => {
                        config.interface.private_key = Some(SecretString::from(key.clone()));
                    }
                    "interface-obfs" => {
                        config.interface.obfuscation_key = Some(SecretString::from(key.clone()));
                    }
                    _ => peer.obfuscation_key = Some(SecretString::from(key.clone())),
                }
                let error =
                    vpn_clients::plan_wireguard_import(fixture.context(), "Wireguard7", &config)
                        .await
                        .err()
                        .ok_or("control character accepted")?;
                assert!(
                    matches!(error, DomainError::Validation { issues: _ }),
                    "{field}: {error:?}"
                );
                assert_eq!(fixture.handle().request_count(), before);
                let shown = format!("{error} {error:?}");
                assert!(
                    !shown.contains(&head) && !shown.contains(&tail),
                    "{field}: the key leaked"
                );
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
