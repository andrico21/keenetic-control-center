//! Planned requests stay exactly as validated, and every line sent renders its request.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the validated-request contract"
)]
mod tests {
    use std::process;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use kcc_app::workflow::CliChangeRequest;
    use kcc_catalog::{HttpMethod, RawAuthorization};
    use kcc_domain::{
        ChangeOp, RouterCtx,
        dns::{self, DnsChange},
        keendns::{self, RemoteSecurityLevel},
        services::{self, ManagementListener, SecurityLevel},
        vpn_clients::{
            self, VpnClientChange,
            secrets::{self, CredentialTarget},
        },
        vpn_servers::{self, VpnServerChange, VpnServerService},
    };
    use kcc_rci::ObjectName;
    use kcc_testkit::model::Firmware;
    use secrecy::SecretString;
    use serde_json::Value;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Every planned request validates again, unchanged, from the body it will send.
    fn assert_revalidates(ctx: &RouterCtx, operation: &ChangeOp) -> TestResult {
        assert!(!operation.requests.is_empty(), "the plan holds requests");
        for request in &operation.requests {
            let wire = request.expose_for_send();
            let again = ctx
                .catalog
                .validate(&request.path, HttpMethod::Post, wire.expose_secret())
                .map_err(|issues| format!("{}: {issues:?}", request.path))?;
            assert_eq!(
                serde_json::to_value(&again)?,
                serde_json::to_value(request)?,
                "{}",
                request.path
            );
        }
        Ok(())
    }

    /// Every line of `request` resolves through the catalog to the request it carries,
    /// and the fake router receives those lines (it records the last line of a batch).
    async fn assert_sent_as_validated(fixture: &Fixture, request: CliChangeRequest) -> TestResult {
        let mut lines = Vec::new();
        for command in &request.commands {
            let line = command.expose_for_send()?.to_string();
            let again = fixture
                .context()
                .catalog
                .validate_cli(&line, RawAuthorization::default())
                .map_err(|issues| format!("{line}: {issues:?}"))?;
            let carried = serde_json::to_value(command.validated())?;
            let rendered = serde_json::to_value(&again)?;
            assert_eq!(rendered.get("path"), carried.get("path"), "{line}");
            assert_eq!(rendered.get("value"), carried.get("value"), "{line}");
            lines.push(line);
        }
        let before = fixture.handle().request_log().len();
        let mut changes = fixture.changes().await?;
        drop(changes.apply_cli(request).await?);
        drop(changes);
        let sent = fixture
            .handle()
            .request_log()
            .iter()
            .skip(before)
            .filter_map(|record| record.command().map(str::to_owned))
            .filter(|command| lines.contains(command))
            .collect::<Vec<_>>();
        assert_eq!(sent.last(), lines.last());
        Ok(())
    }

    /// The `value` member of every request's public projection.
    fn values(operation: &ChangeOp) -> TestResult<Vec<Value>> {
        operation
            .requests
            .iter()
            .map(|request| {
                serde_json::to_value(request)?
                    .get("value")
                    .cloned()
                    .ok_or_else(|| "no value".into())
            })
            .collect()
    }

    /// C-07: the proxy upstream is validated as the body that is sent, not `{}`.
    #[tokio::test]
    async fn proxy_upstream_is_validated_as_sent() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            let proxy = keendns::plan_proxy(ctx, "proxy67", true)?;
            assert_sent_as_validated(&fixture, keendns::change_request(&proxy)?).await?;
            let operation =
                keendns::plan_proxy_upstream(ctx, "proxy67", "http", "192.0.2.67", 8_080)?;
            assert_revalidates(ctx, &operation)?;
            assert_sent_as_validated(&fixture, keendns::change_request(&operation)?).await?;
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// C-07: a security level is validated with its level, not as an empty body.
    #[tokio::test]
    async fn security_levels_are_validated_as_sent() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            let cloud = keendns::plan_cloud_security_level(ctx, RemoteSecurityLevel::Private)?;
            assert_revalidates(ctx, &cloud)?;
            assert_sent_as_validated(&fixture, keendns::change_request(&cloud)?).await?;
            let listener = services::plan_security_level(
                ctx,
                ManagementListener::Ssh,
                SecurityLevel::Protected,
            )?;
            assert_revalidates(ctx, &listener)?;
            assert_sent_as_validated(&fixture, services::change_request(&listener)?).await?;
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-15: VPN client and server plans keep their validated bodies; no line is folded in.
    #[tokio::test]
    async fn vpn_plans_keep_their_validated_bodies() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            for change in [
                VpnClientChange::Create {
                    name: "Wireguard7".to_owned(),
                },
                VpnClientChange::WireGuardListenPort {
                    name: "Wireguard7".to_owned(),
                    port: 51_820,
                },
            ] {
                let operation = vpn_clients::plan_change(ctx, &change).await?;
                assert_revalidates(ctx, &operation)?;
                assert!(
                    values(&operation)?
                        .iter()
                        .all(|value| value.get("line").is_none())
                );
                assert_sent_as_validated(&fixture, vpn_clients::change_request(&operation)?)
                    .await?;
            }
            let server = vpn_servers::plan_change(
                ctx,
                &VpnServerChange::Service {
                    service: VpnServerService::Sstp,
                    enabled: true,
                },
            )?;
            assert_revalidates(ctx, &server)?;
            assert_sent_as_validated(&fixture, vpn_servers::change_request(&server)?).await?;
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-15: secret VPN plans keep the redacted projection of the body they validated.
    #[tokio::test]
    async fn vpn_secret_plans_keep_their_validated_bodies() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            let secret = format!("fixture-{}", process::id());
            let credential = secrets::plan(
                ctx,
                &CredentialTarget::Ike(ObjectName::try_from("office".to_owned())?),
                SecretString::from(secret.clone()),
            )?;
            assert_revalidates(ctx, &credential)?;
            let template = vpn_clients::change_request(&credential)?;
            let [command] = template.commands.as_slice() else {
                return Err("one credential command".into());
            };
            assert!(command.expose_for_send()?.contains(&secret));

            let text = format!(
                "[Interface]\nPrivateKey = {}\nListenPort = 51820\n\n[Peer]\nPublicKey = {}\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 192.0.2.0/24\n",
                base64_key(3),
                base64_key(4)
            );
            let config = vpn_clients::parse_wireguard_config(&text)?;
            let import = vpn_clients::plan_wireguard_import(ctx, "Wireguard7", &config).await?;
            assert_revalidates(ctx, &import)?;
            assert!(
                values(&import)?
                    .iter()
                    .all(|value| value.get("line").is_none())
            );
            let request = vpn_clients::change_request(&import)?;
            let mut changes = fixture.changes().await?;
            drop(changes.apply_cli(request).await?);
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-15: an FQDN group member is validated without the group name folded into its body.
    #[tokio::test]
    async fn fqdn_members_are_validated_as_sent() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            let group = dns::plan_change(
                ctx,
                &DnsChange::FqdnGroup {
                    name: "Blocked".to_owned(),
                },
            )?;
            assert_sent_as_validated(&fixture, dns::change_request(&group)?).await?;
            // The 4.3 catalog types a member `address` as the literal keyword `FQDN`
            // (covered in the dns suite), so only the group itself is planned there.
            if firmware != Firmware::V4_3 {
                for change in [
                    DnsChange::FqdnInclude {
                        name: "Blocked".to_owned(),
                        address: "example.test".to_owned(),
                    },
                    DnsChange::FqdnExclude {
                        name: "Blocked".to_owned(),
                        address: "other.example.test".to_owned(),
                    },
                ] {
                    let operation = dns::plan_change(ctx, &change)?;
                    assert_revalidates(ctx, &operation)?;
                    assert_sent_as_validated(&fixture, dns::change_request(&operation)?).await?;
                }
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// A 32-byte WireGuard key of one repeated byte, encoded at run time.
    fn base64_key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }
}
