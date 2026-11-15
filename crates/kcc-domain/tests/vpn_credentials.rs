//! VPN credential dispatch and read-back contracts.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the credential transport contract"
)]
mod tests {
    use std::process;

    use kcc_app::audit::AUDIT_FILE_NAME;
    use kcc_domain::{
        DomainError,
        vpn_clients::{
            self,
            secrets::{self, CredentialTarget},
        },
    };
    use kcc_rci::ObjectName;
    use kcc_testkit::model::Firmware;
    use secrecy::SecretString;
    use tokio::fs;

    use crate::support::{Fixture, PROFILES, TestResult, TraceCapture, refused_by_catalog};

    /// Every supported credential reaches protected storage and leaves no plaintext output.
    // NOT cancel-safe: applies writes to an isolated fake router.
    #[tokio::test]
    async fn vpn_credentials_are_verified_without_disclosure() -> TestResult {
        for firmware in PROFILES {
            let trace = TraceCapture::install();
            let fixture = Fixture::spawn(firmware).await?;
            let secret = "vpn fixture with \"quote\"";
            let mut changes = fixture.changes().await?;
            for target in [
                CredentialTarget::Ppp(ObjectName::try_from("L2TP7".to_owned())?),
                CredentialTarget::Ppp(ObjectName::try_from("PPTP7".to_owned())?),
                CredentialTarget::Ppp(ObjectName::try_from("SSTP7".to_owned())?),
                CredentialTarget::IpsecInterface(ObjectName::try_from("IPsec7".to_owned())?),
                CredentialTarget::Ike(ObjectName::try_from("office".to_owned())?),
                CredentialTarget::ProfilePreshared(ObjectName::try_from("office".to_owned())?),
                CredentialTarget::ProfileXauth(ObjectName::try_from("office".to_owned())?),
                CredentialTarget::WireGuardObfuscation(ObjectName::try_from(
                    "Wireguard7".to_owned(),
                )?),
                CredentialTarget::WireGuardPeerObfuscation(
                    ObjectName::try_from("Wireguard7".to_owned())?,
                    ObjectName::try_from("publickey".to_owned())?,
                ),
            ] {
                let obfuscation = matches!(
                    target,
                    CredentialTarget::WireGuardObfuscation(_)
                        | CredentialTarget::WireGuardPeerObfuscation(..)
                );
                if firmware == Firmware::V4_3 && obfuscation {
                    // 4.3.9 documents no WireGuard obfuscation keys.
                    let sent = fixture.handle().request_count();
                    let refused =
                        secrets::plan(fixture.context(), &target, SecretString::from(secret));
                    assert!(refused_by_catalog(&refused), "obfuscation key accepted");
                    assert_eq!(fixture.handle().request_count(), sent);
                    continue;
                }
                let plan = secrets::plan(fixture.context(), &target, SecretString::from(secret))?;
                assert!(!format!("{plan:?}").contains(secret));
                secrets::apply(
                    &mut changes,
                    fixture.context(),
                    &target,
                    SecretString::from(secret),
                )
                .await?;
            }
            let stored = fixture.handle().running_config_text();
            for command in [
                "authentication password ns3",
                "ipsec preshared-key ns3",
                "crypto ike key office ns3",
                "preshared-key ns3",
                "xauth-password ns3",
                "wireguard obfs-key ns3",
                "wireguard peer publickey obfs-key ns3",
            ] {
                if firmware == Firmware::V4_3 && command.contains("obfs-key") {
                    assert!(!stored.contains(command), "refused key reached the router");
                    continue;
                }
                assert!(
                    stored.contains(command),
                    "credential representation missing"
                );
            }
            let clients = vpn_clients::read_clients(fixture.context()).await?;
            let audit =
                String::from_utf8(fs::read(fixture.state_dir().join(AUDIT_FILE_NAME)).await?)?;
            for output in [
                stored,
                format!("{:?}", fixture.handle().request_log()),
                audit,
                trace.text()?,
                serde_json::to_string(&clients)?,
                format!("{clients:?}"),
            ] {
                assert!(
                    !output.contains(secret),
                    "credential leaked through an observable boundary"
                );
            }
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Invalid credentials are rejected while planning, with no request or value-bearing error.
    // NOT cancel-safe: creates an isolated fixture.
    #[tokio::test]
    async fn controls_in_credentials_are_rejected_before_io() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let before = fixture.handle().request_count();
            for target in [
                CredentialTarget::Ike(ObjectName::try_from("office".to_owned())?),
                CredentialTarget::WireGuardObfuscation(ObjectName::try_from(
                    "Wireguard7".to_owned(),
                )?),
                CredentialTarget::WireGuardPeerObfuscation(
                    ObjectName::try_from("Wireguard7".to_owned())?,
                    ObjectName::try_from("publickey".to_owned())?,
                ),
            ] {
                let head = format!("credential-head-{}", process::id());
                let tail = format!("credential-tail-{}", process::id());
                let error = secrets::plan(
                    fixture.context(),
                    &target,
                    SecretString::from(format!("{head}\n{tail}")),
                )
                .err()
                .ok_or("control character accepted")?;
                assert!(
                    matches!(error, DomainError::Validation { issues: _ }),
                    "{error:?}"
                );
                assert_eq!(fixture.handle().request_count(), before);
                let shown = format!("{error} {error:?}");
                assert!(
                    !shown.contains(&head) && !shown.contains(&tail),
                    "the credential leaked"
                );
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
