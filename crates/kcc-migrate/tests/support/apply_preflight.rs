//! Preflight acceptance through real workflow services.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "preflight assertions define migration refusal contracts"
)]
mod tests {
    use alloc::sync::Arc;
    use core::error::Error;

    use kcc_app::audit::verify_chain;
    use kcc_migrate::{
        apply::{Applier, ApplyError, ApplySource},
        planner::Choices,
    };
    use kcc_testkit::{
        FakeRouter, FaultInjection, migration,
        model::{Firmware, Model, Profile},
    };
    use secrecy::SecretString;

    use crate::support::Fixture;

    /// Documentation-tier firmware requires explicit audited acknowledgement.
    #[tokio::test]
    async fn documentation_tier_requires_audited_acknowledgement() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::new(Model::Kn1811, Firmware::V4_3)?,
            FaultInjection::default(),
        )
        .await?;
        let unacknowledged = fixture.request(1).await?;
        assert!(matches!(
            Applier::prepare(unacknowledged).await,
            Err(ApplyError::UnverifiedFirmwareTier)
        ));
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        let mut request = fixture.request(1).await?;
        request.options.ack_documentation_tier = true;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert!(
            verify_chain(fixture.state.dir())?
                .iter()
                .any(|event| event.action == "migration.ack_documentation_tier"
                    && event.actor.id == "operator")
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Changed target running configuration is refused before any migration line is sent.
    #[tokio::test]
    async fn target_drift_blocks_apply() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let request = fixture.request(1).await?;
        drop(
            fixture
                .registry
                .client("target")
                .await?
                .parse("interface Bridge8 description external")
                .await?,
        );
        assert!(matches!(
            Applier::prepare(request).await,
            Err(ApplyError::Drift)
        ));
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Live sources cannot alias the target origin.
    #[tokio::test]
    async fn live_source_origin_collision_is_refused() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let mut request = fixture.request(1).await?;
        let client = fixture.registry.client("target").await?;
        assert_eq!(client.router_url(), &fixture.url);
        request.source = ApplySource::LiveRouter {
            id: "target".to_owned(),
            client,
        };
        assert!(matches!(
            Applier::prepare(request).await,
            Err(ApplyError::SameRouter)
        ));
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A distinct stopped live source fails before any target mutation.
    #[tokio::test]
    async fn unreachable_distinct_live_source_is_refused() -> Result<(), Box<dyn Error>> {
        let source = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let client = source.registry.client("target").await?;
        source.handle.shutdown().await?;
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let mut request = fixture.request(1).await?;
        request.source = ApplySource::LiveRouter {
            id: "source".to_owned(),
            client,
        };
        let before = fixture.handle.request_log().len();
        assert!(matches!(
            Applier::prepare(request).await,
            Err(ApplyError::Source)
        ));
        assert!(
            fixture
                .handle
                .request_log()
                .iter()
                .skip(before)
                .all(|entry| entry.method() != "POST" || !entry.path().starts_with("/rci"))
        );
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Stored backup source applies without opening any source router connection.
    #[tokio::test]
    async fn backup_source_applies_without_source_connectivity() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let saved = fixture.handle.startup_config_text();
        let text = SecretString::from(saved.clone());
        let backup = fixture.backups.create("target", "source", &text)?;
        let mut request = fixture.plan_text(saved, &Choices::default()).await?;
        request.source = ApplySource::Backup {
            store: Arc::clone(&fixture.backups),
            router: "target".to_owned(),
            name: backup.name,
        };
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert!(applier.report().verified);
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Factory setup establishes a password and continues with authenticated migration writes.
    #[tokio::test]
    async fn factory_fresh_password_precedes_migration_lines() -> Result<(), Box<dyn Error>> {
        let fake = FakeRouter::builder(Profile::default())
            .user("admin", "", ["cli", "http"])
            .build()?;
        let fixture = Fixture::from_router(fake, "").await?;
        let mut request = fixture.request(1).await?;
        request.options.admin_password =
            Some(SecretString::from("first-admin-password".to_owned()));
        let before = fixture.handle.request_log().len();
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let applier = done.await??;
        assert_eq!(applier.report().failure, None);
        let requests = fixture.handle.request_log();
        let mutations_before_login = requests
            .iter()
            .skip(before)
            .take_while(|entry| !(entry.method() == "POST" && entry.path() == "/auth"))
            .filter(|entry| entry.method() == "POST" && entry.path().starts_with("/rci"))
            .count();
        assert_eq!(
            mutations_before_login, 1,
            "password must be the only mutation before reauthentication"
        );
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        let running = fixture.handle.running_config_text();
        assert!(
            running
                .find("user admin")
                .zip(running.find("migrated-1"))
                .is_some_and(|(admin, line)| admin < line)
        );
        assert!(!format!("{applier:?}").contains("first-admin-password"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Router agreements block until the current document text is explicitly confirmed.
    #[tokio::test]
    async fn agreement_confirmation_is_required_and_audited() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.agreements_required = true;
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "admin").await?;
        let unconfirmed = fixture.request(1).await?;
        assert!(matches!(
            Applier::prepare(unconfirmed).await,
            Err(ApplyError::AgreementRequired)
        ));
        let mut stale = fixture.request(1).await?;
        drop(
            stale
                .options
                .agreements
                .insert("dpn".to_owned(), "Previous document".to_owned()),
        );
        assert!(matches!(
            Applier::prepare(stale).await,
            Err(ApplyError::AgreementRequired)
        ));
        let mut request = fixture.request(1).await?;
        drop(request.options.agreements.insert(
            "dpn".to_owned(),
            "Synthetic router DPN document v1".to_owned(),
        ));
        drop(request.options.agreements.insert(
            "eula".to_owned(),
            "Synthetic router EULA document v1".to_owned(),
        ));
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        let events = verify_chain(fixture.state.dir())?;
        for action in ["migration.confirm_dpn", "migration.confirm_eula"] {
            assert!(
                events
                    .iter()
                    .any(|event| event.action == action && event.actor.id == "operator")
            );
        }
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
