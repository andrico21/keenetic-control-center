//! Deterministic total reconnect budget acceptance.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions define bounded recovery"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{
        error::Error,
        future::ready,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use kcc_migrate::{
        apply::{Applier, ApplyError, Clock},
        planner::Choices,
    };
    use kcc_testkit::{
        FakeRouter,
        model::Profile,
        time::{Clock as _, MockClock},
    };
    use tokio::net::TcpListener;

    use crate::support::Fixture;

    /// Simulates forty seconds of elapsed network and scheduling work per retry delay.
    #[derive(Debug)]
    struct SlowClock {
        time: Arc<MockClock>,
        retries: AtomicUsize,
    }

    impl Clock for SlowClock {
        fn now(&self) -> Duration {
            self.time.now()
        }
        fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            if duration <= Duration::from_secs(1) {
                let _previous = self.retries.fetch_add(1, Ordering::SeqCst);
                self.time.advance(Duration::from_secs(40));
            } else {
                self.time.advance(duration);
            }
            Box::pin(ready(()))
        }
    }

    /// Elapsed time, rather than a fixed attempt count, ends management reconnection.
    #[tokio::test]
    async fn management_reconnect_stops_at_total_clock_budget() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let clock = Arc::new(SlowClock {
            time: Arc::clone(&time),
            retries: AtomicUsize::new(0),
        });
        let fake = FakeRouter::builder(Profile::default())
            .clock(time)
            .build()?;
        let fixture = Fixture::from_router(fake, "admin").await?;
        let unavailable = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}", unavailable.local_addr()?);
        drop(unavailable);
        let choices = Choices::default().with_reconnect_url(url);
        let mut request = fixture.plan_text("! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\ninterface Bridge0\n ip address 198.51.100.1 255.255.255.0\n!\n".to_owned(), &choices).await?;
        request.options.clock = Arc::<SlowClock>::clone(&clock);
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let applier = done.await??;
        assert_eq!(clock.retries.load(Ordering::SeqCst), 3);
        assert_eq!(
            applier.report().failure,
            Some(ApplyError::RolledBackByRouter)
        );
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
