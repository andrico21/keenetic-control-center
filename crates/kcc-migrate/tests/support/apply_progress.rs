//! Job progress and long-running recovery-timer acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions define job progress and recovery contracts"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, future::ready, pin::Pin, time::Duration};

    use kcc_app::{audit::verify_chain, jobs::JobProgress};
    use kcc_migrate::apply::{Applier, Clock};
    use kcc_testkit::{
        FakeRouter, FaultInjection, migration,
        model::Profile,
        time::{Clock as _, MockClock},
    };
    use tokio::time::timeout;

    use crate::support::Fixture;

    /// Each complete group of fifty replayed lines renews recovery before the next group.
    #[tokio::test]
    async fn every_fifty_line_boundary_renews_recovery() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let (_id, done) = Applier::start(&fixture.runner, fixture.request(105).await?).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        let mut submitted = 0_usize;
        let mut boundaries = Vec::new();
        for event in verify_chain(fixture.state.dir())? {
            if event.action == "router.migration_replay" {
                submitted = submitted.saturating_add(1);
            }
            if event.target.as_deref() == Some("system configuration fail-safe keep-alive") {
                boundaries.push(submitted);
            }
        }
        assert_eq!(boundaries, [50, 100, 105]);
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Advances simulated elapsed work when the applier checks its monotonic clock.
    #[derive(Debug)]
    struct WorkClock(Arc<MockClock>);

    impl Clock for WorkClock {
        fn now(&self) -> Duration {
            self.0.advance(Duration::from_secs(20));
            self.0.now()
        }
        fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.0.advance(duration);
            Box::pin(ready(()))
        }
    }

    /// More than a timer's worth of work succeeds with each line reported and no implicit save.
    #[tokio::test]
    async fn long_apply_renews_timer_and_emits_each_line() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?;
        let fixture = Fixture::from_router(fake, "admin").await?;
        let mut request = fixture.request(55).await?;
        request.options.clock = Arc::new(WorkClock(Arc::clone(&clock)));
        request.options.safety_seconds = 300;
        let mut events = fixture.runner.subscribe();
        let (id, done) = Applier::start(&fixture.runner, request).await?;
        let mut indices = Vec::new();
        while indices.len() < 55 {
            let event = timeout(Duration::from_secs(15), events.recv()).await??;
            if event.id == id
                && let Some(JobProgress::Structured(value)) = event.detail
                && let Some(index) = value
                    .get("source_index")
                    .and_then(serde_json::Value::as_u64)
            {
                indices.push(index);
            }
        }
        let mut applier = done.await??;
        assert_eq!(indices, (0..55_u64).collect::<Vec<_>>());
        assert_eq!(applier.report().failure, None);
        assert!(clock.now() > Duration::from_secs(300));
        assert!(!fixture.handle.startup_config_text().contains("migrated-"));
        applier.rollback().await?;
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Dropping an uncommitted AP migration leaves scheduled reboot to restore saved state.
    #[tokio::test]
    async fn uncommitted_access_point_migration_rolls_back_on_timer() -> Result<(), Box<dyn Error>>
    {
        let clock = Arc::new(MockClock::new());
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("ap".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "admin").await?;
        let before = fixture.handle.startup_config_text();
        let (_id, done) = Applier::start(&fixture.runner, fixture.request(1).await?).await?;
        let applier = done.await??;
        assert!(applier.report().verified);
        assert!(fixture.handle.running_config_text().contains("migrated-1"));
        drop(applier);
        clock.advance(Duration::from_secs(901));
        drop(fixture.registry.poll_info("target").await?);
        assert_eq!(fixture.handle.startup_config_text(), before);
        assert!(!fixture.handle.running_config_text().contains("migrated-1"));
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
