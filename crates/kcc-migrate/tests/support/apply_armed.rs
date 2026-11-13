//! Recovery timer outcome when preflight stops after arming.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish recovery outcomes"
)]
mod tests {
    use core::error::Error;

    use kcc_migrate::apply::{Applier, ApplyError};
    use kcc_testkit::{FakeRouter, FaultInjection, Handle, migration, model::Profile};

    use crate::support::Fixture;

    /// Recovery-timer disarm line for the default fake's fail-safe mode.
    const DISARM: &str = "no system configuration fail-safe timer";

    /// Opens a target that requires agreement acceptance, with `faults` injected.
    async fn target(faults: FaultInjection) -> Result<Fixture, Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.agreements_required = true;
        let fake = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?
            .with_migration(scenario);
        Fixture::from_router(fake, "admin").await
    }

    /// Runs preflight with both agreements confirmed and `components` requested.
    async fn prepare(
        fixture: &Fixture,
        components: &[&str],
    ) -> Result<Result<Applier, ApplyError>, Box<dyn Error>> {
        let mut request = fixture.request(1).await?;
        for (agreement, text) in [
            ("dpn", "Synthetic router DPN document v1"),
            ("eula", "Synthetic router EULA document v1"),
        ] {
            drop(
                request
                    .options
                    .agreements
                    .insert(agreement.to_owned(), text.to_owned()),
            );
        }
        request
            .options
            .install_components
            .extend(components.iter().map(|name| (*name).to_owned()));
        Ok(Applier::prepare(request).await)
    }

    /// Parser lines the target received.
    fn commands(handle: &Handle) -> Vec<String> {
        handle
            .request_log()
            .into_iter()
            .filter_map(|record| record.command().map(str::to_owned))
            .collect()
    }

    /// A refused agreement after arming disarms the timer and keeps the original error.
    #[tokio::test]
    async fn initialize_failure_after_arm_disarms() -> Result<(), Box<dyn Error>> {
        let fixture =
            target(FaultInjection::default().fail_parse_matching("dpn accept", 1)).await?;
        let outcome = prepare(&fixture, &[]).await?;
        assert!(
            matches!(outcome, Err(ApplyError::Stopped)),
            "unexpected outcome: {outcome:?}"
        );
        assert!(!fixture.handle.recovery_armed());
        assert!(commands(&fixture.handle).iter().any(|line| line == DISARM));
        assert!(!fixture.handle.running_config_text().contains("migrated-1"));
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A refused disarm after a failed step reports the timer as armed.
    #[tokio::test]
    async fn refused_disarm_after_arm_reports_armed() -> Result<(), Box<dyn Error>> {
        let fixture = target(FaultInjection::default().fail_parse_matching("no system", 1)).await?;
        let outcome = prepare(&fixture, &["not_a_component"]).await?;
        assert!(fixture.handle.recovery_armed());
        assert!(commands(&fixture.handle).iter().any(|line| line == DISARM));
        let Err(error) = outcome else {
            return Err("preflight unexpectedly succeeded".into());
        };
        assert_eq!(error, ApplyError::FinishFailed);
        assert!(error.recovery_armed());
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A refused arm is followed by a disarm; only a refused disarm reports a possible timer.
    #[tokio::test]
    async fn refused_arm_is_disarmed_or_reported() -> Result<(), Box<dyn Error>> {
        for (refusals, expected) in [(1, ApplyError::Workflow), (2, ApplyError::ArmUnconfirmed)] {
            let fixture =
                target(FaultInjection::default().fail_parse_matching("fail-safe timer", refusals))
                    .await?;
            let outcome = prepare(&fixture, &[]).await?;
            let Err(error) = outcome else {
                return Err("preflight unexpectedly succeeded".into());
            };
            assert_eq!(error, expected);
            assert_eq!(error.recovery_armed(), refusals == 2);
            assert!(!fixture.handle.recovery_armed());
            let sent = commands(&fixture.handle);
            assert!(sent.iter().any(|line| line == DISARM));
            assert!(!sent.iter().any(|line| line.ends_with(" accept")));
            fixture.handle.shutdown().await?;
        }
        Ok(())
    }
}
