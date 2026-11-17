//! Secret replay acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish secret-safe execution"
)]
mod tests {
    use core::error::Error;

    use kcc_app::audit::verify_chain;
    use kcc_config::ns3;
    use kcc_migrate::{apply::Applier, planner::Choices};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
    use secrecy::SecretString;

    use crate::support::Fixture;

    /// NS3 is sent encoded first; only an explicit rejection permits protected plaintext retry.
    #[tokio::test]
    async fn ns3_rejection_uses_protected_plaintext_retry() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.reject_ns3 = true;
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "admin").await?;
        let secret = "migrated-wifi-secret";
        let encoded = ns3::encode(&SecretString::from(secret.to_owned()))?;
        let text = format!(
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface WifiMaster0/AccessPoint9\n authentication wpa-psk ns3 {encoded}\n!\n"
        );
        let request = fixture.plan_text(text, &Choices::default()).await?;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert!(fixture.handle.running_config_text().contains(&encoded));
        let events = verify_chain(fixture.state.dir())?;
        let outcomes = events
            .iter()
            .filter(|event| event.action == "router.migration_replay")
            .map(|event| {
                event
                    .params_redacted
                    .pointer("/outcomes/0")
                    .and_then(serde_json::Value::as_str)
            })
            .collect::<Vec<_>>();
        assert_eq!(outcomes, [Some("Rejected"), Some("Applied")]);
        let public = format!(
            "{applier:?} {}",
            serde_json::to_string(&verify_chain(fixture.state.dir())?)?
        );
        assert!(!public.contains(secret));
        assert!(!public.contains(&encoded));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Management password commands use a fresh credential and rollback restores the old login.
    #[tokio::test]
    async fn management_password_reconnects_and_rollback_restores_credentials()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let secret = "new-management-secret";
        let choices = Choices::default().with_reconnect_url(fixture.url.as_str().to_owned());
        let text = format!(
            "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\nuser admin password plain {secret}\n"
        );
        let mut request = fixture.plan_text(text, &choices).await?;
        request.options.management_password = Some(SecretString::from(secret.to_owned()));
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        applier.rollback().await?;
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        assert!(!fixture.handle.running_config_text().contains("user admin"));
        assert!(!serde_json::to_string(&verify_chain(fixture.state.dir())?)?.contains(secret));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
