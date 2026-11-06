//! Recovery and management migration acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish recovery outcomes"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, future::ready, pin::Pin, time::Duration};

    use kcc_migrate::{
        apply::{Applier, ApplyError, Clock},
        planner::Choices,
    };
    use kcc_testkit::{
        FakeRouter, migration,
        model::Profile,
        time::{Clock as _, MockClock},
    };
    use tokio::net::TcpListener;

    use crate::support::Fixture;

    /// Shared deterministic clock advances only when the applier requests recovery waiting.
    #[derive(Debug)]
    struct RecoveryClock(Arc<MockClock>);

    impl Clock for RecoveryClock {
        fn now(&self) -> Duration {
            self.0.now()
        }
        fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.0.advance(duration);
            Box::pin(ready(()))
        }
    }

    /// Component prerequisites reboot and re-inventory without applying the stale plan.
    #[tokio::test]
    async fn component_install_requires_a_fresh_plan() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?;
        let fixture = Fixture::from_router(fake, "admin").await?;
        let mut request = fixture.request(1).await?;
        request.options.clock = Arc::new(RecoveryClock(clock));
        request
            .options
            .install_components
            .push("wireguard".to_owned());
        let outcome = Applier::prepare(request).await;
        assert!(
            matches!(outcome, Err(ApplyError::ReplanRequired)),
            "unexpected prerequisite outcome: {outcome:?}"
        );
        assert!(
            fixture
                .registry
                .poll_info("target")
                .await?
                .components
                .contains("wireguard")
        );
        assert!(!fixture.handle.running_config_text().contains("migrated-1"));
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// The lost router restores original startup state when its timer expires.
    #[tokio::test]
    async fn router_loss_reports_router_rollback_after_timer() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let mut scenario = migration::Fixture::default();
        scenario.loss_until = Some(Duration::from_secs(301));
        scenario.mode = Some("router".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "admin").await?;
        let mut request = fixture.request(2).await?;
        request.options.clock = Arc::new(RecoveryClock(clock));
        request.options.safety_seconds = 300;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let applier = done.await??;
        assert_eq!(
            applier.report().failure,
            Some(ApplyError::RolledBackByRouter)
        );
        assert!(!fixture.handle.running_config_text().contains("migrated-"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Non-router modes use scheduled reboot and do not leave it armed after explicit commit.
    #[tokio::test]
    async fn access_point_mode_uses_scheduled_reboot() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("ap".to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::from_router(fake, "admin").await?;
        let request = fixture.request(1).await?;
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(applier.report().failure, None);
        applier.commit().await?;
        clock.advance(Duration::from_secs(1000));
        let info = fixture.registry.poll_info("target").await?;
        assert_eq!(info.hw_id(), Some("KN-1811"));
        assert!(fixture.handle.startup_config_text().contains("migrated-1"));
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A management address change requires a new reachable URL, then rollback uses the old URL.
    #[tokio::test]
    async fn management_address_reconnects_to_new_listener() -> Result<(), Box<dyn Error>> {
        for old_endpoint_survives in [false, true] {
            let fake = FakeRouter::builder(Profile::default()).build()?;
            let alternate = TcpListener::bind(("127.0.0.1", 0)).await?;
            let new_address = alternate.local_addr()?;
            drop(alternate);
            let new_url = format!("http://{new_address}");
            let second = fake.clone();
            let fixture = Fixture::from_router(fake.clone(), "admin").await?;
            let mut scenario = migration::Fixture::default();
            scenario.management = (!old_endpoint_survives).then(|| {
                (
                    fixture
                        .url
                        .as_str()
                        .trim_start_matches("http://")
                        .trim_end_matches('/')
                        .to_owned(),
                    new_address.to_string(),
                    "198.51.100.1".to_owned(),
                )
            });
            drop(fake.with_migration(scenario));
            let (_address, second_handle) = second.serve(new_address).await?;
            let choices = Choices::default().with_reconnect_url(new_url.clone());
            let text = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge0\n ip address 198.51.100.1 255.255.255.0\n!\n".to_owned();
            let request = fixture.plan_text(text, &choices).await?;
            let (_id, done) = Applier::start(&fixture.runner, request).await?;
            let mut applier = done.await??;
            assert_eq!(applier.report().failure, None);
            assert_eq!(
                fixture
                    .registry
                    .client("target")
                    .await?
                    .router_url()
                    .as_str()
                    .trim_end_matches('/'),
                new_url
            );
            applier.rollback().await?;
            assert!(
                !fixture
                    .handle
                    .running_config_text()
                    .contains("198.51.100.1")
            );
            drop(applier);
            second_handle.shutdown().await?;
            fixture.handle.shutdown().await?;
        }
        Ok(())
    }
}
