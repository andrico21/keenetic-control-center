//! VPN server credential and explicit reveal-gate coverage.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the reveal permission boundary"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use kcc_domain::{
        DomainError,
        vpn_clients::secrets::CredentialTarget,
        vpn_servers::{
            self,
            secrets::{self, RevealSecrets},
        },
    };
    use kcc_rci::ObjectName;
    use secrecy::{ExposeSecret as _, SecretString};

    use crate::support::{Fixture, TestResult};

    /// Reveal requires both the capability and the requested router scope, before I/O.
    // NOT cancel-safe: creates an isolated fake router.
    #[tokio::test]
    async fn reveal_refuses_missing_permission_and_wrong_scope() -> TestResult {
        let fixture = Fixture::spawn().await?;
        let before = fixture.handle().request_count();
        for role in [
            Role::new(
                "viewer".to_owned(),
                [Permission::Read],
                vec!["*".to_owned()],
            ),
            Role::new(
                "other".to_owned(),
                [Permission::RevealSecrets],
                vec!["other".to_owned()],
            ),
        ] {
            assert!(matches!(
                RevealSecrets::authorize(&role, "router", fixture.context()),
                Err(DomainError::PermissionDenied)
            ));
        }
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await
    }

    /// Default reads omit credentials; explicit reveal returns only protected stored data.
    // NOT cancel-safe: applies writes to an isolated fake router.
    #[tokio::test]
    async fn server_credentials_require_explicit_reveal() -> TestResult {
        let fixture = Fixture::spawn().await?;
        let name = ObjectName::try_from("vpn-user".to_owned())?;
        let secret = "server fixture credential";
        let plan = secrets::plan_password(fixture.context(), &name, SecretString::from(secret))?;
        let mut changes = fixture.changes().await?;
        drop(changes.apply_cli(secrets::password_request(&plan)?).await?);
        let key_name = ObjectName::try_from("server-key".to_owned())?;
        secrets::apply_ike_psk(
            &mut changes,
            fixture.context(),
            key_name.clone(),
            SecretString::from(secret),
        )
        .await?;

        let default = vpn_servers::read_servers(fixture.context()).await?;
        assert!(!serde_json::to_string(&default)?.contains(secret));
        let role = Role::new(
            "reveal".to_owned(),
            [Permission::RevealSecrets],
            vec!["router".to_owned()],
        );
        let gate = RevealSecrets::authorize(&role, "router", fixture.context())?;
        let stored = gate
            .read_stored(&CredentialTarget::Ike(key_name))
            .await?
            .ok_or("stored key absent")?;
        assert!(stored.expose_secret().starts_with("ns3 "));
        assert!(
            stored.expose_secret().len() > 4,
            "stored payload must be present"
        );
        assert!(!format!("{stored:?} {gate:?}").contains(secret));
        drop(changes);
        fixture.shutdown().await
    }
}
