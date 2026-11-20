//! Recovery timer outcome when preflight stops after arming.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish recovery outcomes"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, pin::Pin, time::Duration};

    use kcc_app::{
        audit::{Actor, ActorKind},
        workflow::WorkflowError,
    };
    use kcc_migrate::apply::{Applier, ApplyError, ApplyRequest, Clock};
    use kcc_testkit::{FakeRouter, FaultInjection, Handle, migration, model::Profile};
    use tokio::{sync::watch, time::timeout};

    use crate::support::Fixture;

    /// Recovery-timer disarm line for the default fake's fail-safe mode.
    const DISARM: &str = "no system configuration fail-safe timer";

    /// Upper bound of every wait.
    const WAIT: Duration = Duration::from_secs(60);

    /// An apply clock whose waits end only once the test opens it; it records every wait.
    #[derive(Debug, Default)]
    struct Gate {
        /// Every wait asked for, in order.
        asked: watch::Sender<Vec<Duration>>,
        /// Whether waits end.
        open: watch::Sender<bool>,
    }

    impl Clock for Gate {
        fn now(&self) -> Duration {
            Duration::ZERO
        }

        fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.asked.send_modify(|asked| asked.push(duration));
            let mut open = self.open.subscribe();
            Box::pin(async move {
                drop(open.wait_for(|opened| *opened).await);
            })
        }
    }

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
        let input = request(fixture, components).await?;
        Ok(Applier::prepare(input).await)
    }

    /// A request with both agreements confirmed and `components` requested.
    async fn request(
        fixture: &Fixture,
        components: &[&str],
    ) -> Result<ApplyRequest, Box<dyn Error>> {
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
        Ok(request)
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

    /// Todo 21: a held failure keeps the job and the lease until the timer ran out.
    ///
    /// The disarm after a failed step is refused, so the timer may still run: the failure
    /// arrives at once, and the job keeps the router's lease until the timer's interval and
    /// one second more have passed on the apply clock.
    #[tokio::test]
    async fn a_held_armed_failure_keeps_the_lease_until_the_timer_ran_out()
    -> Result<(), Box<dyn Error>> {
        let fixture = target(FaultInjection::default().fail_parse_matching("no system", 1)).await?;
        let clock = Arc::new(Gate::default());
        let mut held = request(&fixture, &["not_a_component"]).await?;
        held.options.clock = Arc::<Gate>::clone(&clock);
        held.options.hold_armed_failure = true;
        let interval = Duration::from_secs(held.options.safety_seconds.saturating_add(1));
        let operator = Actor::new(ActorKind::Cli, "cli:operator".to_owned());
        let mut asked = clock.asked.subscribe();

        let (job, done) = Applier::start(&fixture.runner, held).await?;

        assert_eq!(
            timeout(WAIT, done).await??.err(),
            Some(ApplyError::FinishFailed)
        );
        drop(timeout(WAIT, asked.wait_for(|seen| seen.contains(&interval))).await??);
        let busy = fixture.workflow.reserve("target", &operator, &fixture.role);
        assert!(
            matches!(busy, Err(WorkflowError::RouterBusy { actor: _ })),
            "{busy:?}"
        );
        clock.open.send_modify(|open| *open = true);
        timeout(WAIT, fixture.runner.ended(&job)).await?;
        drop(
            fixture
                .workflow
                .reserve("target", &operator, &fixture.role)?,
        );
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
