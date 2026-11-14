//! Log destination retry policy contracts.

use core::{fmt, future::ready, pin::Pin, time::Duration};
use std::sync::{Arc, Mutex};

use chrono::{FixedOffset, TimeZone as _};
use kcc_app::settings::Config;
use kcc_telemetry::{
    logs::{pipeline::LogForwarder, retry::Clock},
    metrics::instrumentation::SelfMetrics,
};
use kcc_testkit::fake_loki::{FakeLoki, Fault};

use super::{TestResult, record};

#[derive(Default)]
struct RecordingClock {
    waits: Mutex<Vec<Duration>>,
}

impl fmt::Debug for RecordingClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingClock")
    }
}

impl Clock for RecordingClock {
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match self.waits.lock() {
            Ok(mut waits) => waits.push(duration),
            Err(poisoned) => poisoned.into_inner().push(duration),
        }
        Box::pin(ready(()))
    }
}

#[tokio::test]
async fn retry_after_delays_loki_retry_by_at_least_two_seconds() -> TestResult {
    let fake =
        FakeLoki::spawn_with_faults(vec![Fault::TooManyRequests(Duration::from_secs(2))]).await?;
    let config = Config::from_toml_str(&format!(
        "[logs]\nenabled = true\n\n[[logs.sinks]]\nkind = \"loki\"\nurl = \"{}\"\n",
        fake.url()
    ))?;
    config.validate()?;
    let offset = FixedOffset::east_opt(0).ok_or("offset")?;
    let timestamp = offset
        .with_ymd_and_hms(2026, 11, 7, 12, 0, 1)
        .single()
        .ok_or("date")?;
    let clock = Arc::new(RecordingClock::default());
    let metrics = SelfMetrics::new("retry-test")?;
    let shared: Arc<dyn Clock> = Arc::<RecordingClock>::clone(&clock);
    let pipeline = LogForwarder::start_with_clock(&config.logs, metrics, shared).await?;

    pipeline.push(&record(13, timestamp, "retry-after"));
    pipeline.shutdown().await;

    let waits = match clock.waits.lock() {
        Ok(waits) => waits.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert_eq!(waits, [Duration::from_secs(2)]);
    assert_eq!(fake.requests().len(), 2);
    fake.shutdown().await?;
    Ok(())
}
