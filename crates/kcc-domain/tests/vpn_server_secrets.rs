//! VPN server credential coverage.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the credential read boundary"
)]
mod tests {
    use kcc_domain::{
        router_users::protection::OwnLogins,
        vpn_servers::{self, secrets},
    };
    use kcc_rci::ObjectName;
    use secrecy::SecretString;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Server reads omit the credentials that were just written.
    // NOT cancel-safe: applies writes to an isolated fake router.
    #[tokio::test]
    async fn server_reads_omit_credentials() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let name = ObjectName::try_from("vpn-user".to_owned())?;
            let secret = "server fixture credential";
            let plan = secrets::plan_password(
                fixture.context(),
                &name,
                &OwnLogins::new("admin", None)?,
                SecretString::from(secret),
            )?;
            let mut changes = fixture.changes().await?;
            drop(changes.apply_cli(secrets::password_request(&plan)?).await?);
            let key_name = ObjectName::try_from("server-key".to_owned())?;
            secrets::apply_ike_psk(
                &mut changes,
                fixture.context(),
                key_name,
                SecretString::from(secret),
            )
            .await?;

            let default = vpn_servers::read_servers(fixture.context()).await?;
            assert!(!serde_json::to_string(&default)?.contains(secret));
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
