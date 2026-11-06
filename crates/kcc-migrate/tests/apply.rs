//! Migration apply acceptance through real jobs and the fake router.
extern crate alloc;

#[path = "support/apply_offline.rs"]
mod offline;

#[path = "support/apply_lifecycle.rs"]
mod lifecycle;
#[path = "support/apply_policy.rs"]
mod policy;
#[path = "support/apply_preflight.rs"]
mod preflight;
#[path = "support/apply_progress.rs"]
mod progress;
#[path = "support/apply_raw.rs"]
mod raw;
#[path = "support/apply_reconnect.rs"]
mod reconnect;
#[path = "support/apply_secrets.rs"]
mod secrets;
#[path = "support/apply_fixture.rs"]
mod support;
#[path = "support/apply_trace.rs"]
mod trace;
#[path = "support/apply_verification.rs"]
mod verification;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish migration safety"
)]
mod tests {
    use core::error::Error;

    use kcc_migrate::{
        apply::{Applier, ApplyError},
        planner::Choices,
    };
    use kcc_testkit::{FaultInjection, model::Profile};

    use super::support::Fixture;

    /// A file migration applies and verifies without saving until explicit commit.
    #[tokio::test]
    async fn file_apply_verifies_then_explicit_commit_saves_every_line()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let request = fixture.request(20).await?;
        let expected = request
            .plan
            .phases
            .additive
            .iter()
            .map(|line| line.expose_command().to_owned())
            .collect::<Vec<_>>();
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        assert!(applier.report().verified);
        assert!(!fixture.handle.startup_config_text().contains("migrated-"));
        applier.commit().await?;
        let startup = fixture.flattened_startup()?;
        for line in expected {
            assert!(startup.contains(&line), "planned line missing after commit");
        }
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Line 17 rejection stops before line 18 and explicit rollback restores startup identity.
    #[tokio::test]
    async fn line_17_stops_and_rollback_restores_startup() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().fail_parse_matching("migrated-17", 1),
        )
        .await?;
        let before = fixture.handle.startup_config_text();
        let request = fixture.request(20).await?;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, Some(ApplyError::Stopped));
        assert_eq!(applier.report().applied.len(), 16);
        assert!(!fixture.handle.running_config_text().contains("migrated-18"));
        assert!(
            applier.commit().await.is_err(),
            "partial migration must not commit"
        );
        applier.rollback().await?;
        assert_eq!(fixture.handle.startup_config_text(), before);
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Explicit commit refuses a same-agent change made after verification.
    #[tokio::test]
    async fn commit_refuses_post_verification_drift() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let (_id, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let mut applier = done.await??;
        assert!(applier.report().verified);
        drop(
            fixture
                .registry
                .client("target")
                .await?
                .parse("interface Bridge8 description external")
                .await?,
        );
        assert_eq!(applier.commit().await, Err(ApplyError::Drift));
        assert!(!fixture.handle.startup_config_text().contains("external"));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Startup replay cannot smuggle a persistence command into the additive phase.
    #[tokio::test]
    async fn replay_refuses_embedded_save_before_any_write() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let request = fixture
            .plan_text(
                "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\nsystem configuration save\n"
                    .to_owned(),
                &Choices::default(),
            )
            .await?;
        assert!(matches!(
            Applier::prepare(request).await,
            Err(ApplyError::Validation)
        ));
        assert!(
            fixture.backups.list("target")?.is_empty(),
            "refusal must precede the first protected write"
        );
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A successful parser receipt cannot replace actual configuration read-back.
    #[tokio::test]
    async fn acknowledged_noop_fails_verification_and_cannot_commit() -> Result<(), Box<dyn Error>>
    {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().silent_noop_path("parse"),
        )
        .await?;
        let (_id, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, Some(ApplyError::Verification));
        assert_eq!(applier.commit().await, Err(ApplyError::Verification));
        assert!(!fixture.handle.startup_config_text().contains("migrated-"));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
