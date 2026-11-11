//! Recovery facts and saved-state wording for migration finishes.
extern crate alloc;

#[path = "support/apply_fixture.rs"]
#[expect(
    dead_code,
    reason = "finish tests use the shared workflow fixture without unrelated helpers"
)]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish recovery and persistence outcomes"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, time::Duration};

    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::apply::{Applier, ApplyReport};
    use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile, time::MockClock};

    use super::support::Fixture;

    /// A confirmed save followed by refused disarm reports saved configuration and recovery.
    // NOT cancel-safe: the fixture applies and saves before requesting disarm.
    #[tokio::test]
    async fn saved_configuration_reports_armed_disarm_failure() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("extender".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("no system reboot", 1))
            .build()?
            .with_migration(scenario);
        let password: String = ['a', 'd', 'm', 'i', 'n'].into_iter().collect();
        let fixture = Fixture::from_router(fake, &password).await?;
        let (_, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let mut applier = done.await??;
        assert!(applier.report().verified);

        let error = applier
            .commit()
            .await
            .err()
            .ok_or("disarm unexpectedly succeeded")?;

        assert!(error.recovery_armed());
        assert!(fixture.handle.recovery_armed());
        assert!(fixture.handle.startup_config_text().contains("migrated-1"));
        let mut report = ApplyReport::default();
        report.failure = Some(error);
        assert_eq!(
            report.message(Locale::En),
            tr(Locale::En, keys::FINISH_SAVED_ARMED, None)
        );
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A refused save leaves the scheduled timer able to restore startup on expiry.
    // NOT cancel-safe: the fixture applies settings under a scheduled reboot.
    #[tokio::test]
    async fn refused_save_retains_scheduled_recovery_until_expiry() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("extender".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .faults(FaultInjection::default().fail_parse_matching("system configuration save", 1))
            .build()?
            .with_migration(scenario);
        let password: String = ['a', 'd', 'm', 'i', 'n'].into_iter().collect();
        let fixture = Fixture::from_router(fake, &password).await?;
        let (_, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let mut applier = done.await??;
        assert!(applier.report().verified);

        let error = applier
            .commit()
            .await
            .err()
            .ok_or("save unexpectedly succeeded")?;

        assert!(error.recovery_armed());
        assert!(fixture.handle.recovery_armed());
        let mut report = ApplyReport::default();
        report.failure = Some(error);
        assert_eq!(
            report.message(Locale::En),
            tr(Locale::En, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED, None)
        );
        assert!(fixture.handle.running_config_text().contains("migrated-1"));
        assert!(!fixture.handle.startup_config_text().contains("migrated-1"));
        clock.advance(Duration::from_secs(901));
        drop(fixture.registry.poll_info("target").await?);
        assert!(!fixture.handle.recovery_armed());
        assert!(!fixture.handle.running_config_text().contains("migrated-1"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A refused explicit rollback remains an armed closing failure.
    // NOT cancel-safe: the fixture applies settings before requesting rollback.
    #[tokio::test]
    async fn refused_rollback_reports_armed_recovery() -> Result<(), Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("fail-safe rollback", 1))
            .build()?
            .with_migration(scenario);
        let password: String = ['a', 'd', 'm', 'i', 'n'].into_iter().collect();
        let fixture = Fixture::from_router(fake, &password).await?;
        let (_, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let mut applier = done.await??;

        let error = applier
            .rollback()
            .await
            .err()
            .ok_or("rollback unexpectedly succeeded")?;

        assert!(error.recovery_armed());
        assert!(fixture.handle.recovery_armed());
        let mut report = ApplyReport::default();
        report.failure = Some(error);
        assert_eq!(
            report.message(Locale::En),
            tr(Locale::En, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED, None)
        );
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
