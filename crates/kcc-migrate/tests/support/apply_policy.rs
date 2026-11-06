//! Stop-policy and exhausted-retry acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions protect replay failure policy"
)]
mod tests {
    use core::error::Error;

    use kcc_migrate::{
        apply::{Applier, ApplyError, StopPolicy},
        planner::Choices,
    };
    use kcc_testkit::{FaultInjection, model::Profile};

    use crate::support::Fixture;

    /// Permissive mode still stops before later lines when the rejected line is critical.
    #[tokio::test]
    async fn continue_policy_stops_on_critical_rejection() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().fail_parse_matching("198.51.100.8", 1),
        )
        .await?;
        let mut request = fixture
            .plan_text(
                "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge18\n ip address 198.51.100.8 255.255.255.0\n!\ninterface Bridge19\n description later-line\n!\n".to_owned(),
                &Choices::default(),
            )
            .await?;
        request.options.stop_policy = StopPolicy::ContinueOnNonCritical;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, Some(ApplyError::Stopped));
        assert_eq!(applier.report().failed, [0]);
        assert!(
            applier.report().applied.is_empty(),
            "critical failure stops replay"
        );
        assert!(!fixture.handle.running_config_text().contains("later-line"));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A second rejection is retained as a failure and cannot silently become a committed plan.
    #[tokio::test]
    async fn exhausted_deferred_retry_remains_failed() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().fail_parse_matching("migrated-1", 2),
        )
        .await?;
        let mut request = fixture.request(3).await?;
        request.options.stop_policy = StopPolicy::ContinueOnNonCritical;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, Some(ApplyError::Stopped));
        assert_eq!(applier.report().failed, [0]);
        assert_eq!(applier.report().applied, [1, 2]);
        assert!(!fixture.handle.running_config_text().contains("migrated-1"));
        assert_eq!(applier.commit().await, Err(ApplyError::Verification));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
