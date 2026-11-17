//! What the integration fixture wires around the Web UI (a hand-moved clock, the update
//! check reporting each finished check, the router log collector, the options) and the
//! response helpers.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever setup step failed"
)]

use core::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axum::{body::to_bytes, http::header, response::Response};
use kcc_app::{accounts::Clock, registry::RouterRegistry, settings::Config};
use kcc_telemetry::{logs::runtime::Service as LogService, metrics::instrumentation::SelfMetrics};
use kcc_testkit::{FaultInjection, firmware_update::FirmwareUpdate};
use kcc_web::{
    fleet::{UpdateCheck, UpdateStatus},
    fleet_updates::ComponentsUpdateCheck,
};
use tokio::sync::mpsc;

use crate::support::TestResult;

/// A clock the tests move by hand.
#[derive(Debug)]
pub(crate) struct HandClock(AtomicU64);

impl Clock for HandClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl HandClock {
    /// A clock showing `now`.
    pub(crate) const fn new(now: AtomicU64) -> Self {
        Self(now)
    }

    /// Moves the clock `by` forward.
    pub(crate) fn advance(&self, by: Duration) {
        let _previous: u64 = self.0.fetch_add(by.as_secs(), Ordering::SeqCst);
    }
}

/// The real update check, reporting every finished check on a channel.
pub(crate) struct Reporting {
    /// The check under test.
    inner: ComponentsUpdateCheck,
    /// Receives each result.
    done: mpsc::UnboundedSender<UpdateStatus>,
}

impl Reporting {
    /// `inner`, reporting to `done`.
    pub(crate) const fn new(
        inner: ComponentsUpdateCheck,
        done: mpsc::UnboundedSender<UpdateStatus>,
    ) -> Self {
        Self { inner, done }
    }
}

impl UpdateCheck for Reporting {
    fn check<'call>(
        &'call self,
        router: &'call str,
    ) -> Pin<Box<dyn Future<Output = UpdateStatus> + Send + 'call>> {
        Box::pin(async move {
            let status = self.inner.check(router).await;
            drop(self.done.send(status.clone()));
            status
        })
    }

    fn cached(&self, router: &str) -> (UpdateStatus, bool) {
        self.inner.cached(router)
    }
}

/// What the fixture wires around the Web UI.
#[derive(Debug, Default)]
pub(crate) struct Options {
    /// The fake's `components check-update` answer; `Some` attaches the update check.
    update: Option<FirmwareUpdate>,
    /// Failures injected into the fake router.
    faults: FaultInjection,
    /// Runs the router's log collector (`[logs] enabled`) and lets the log page follow it.
    collector: bool,
}

impl Options {
    /// The update check attached, the fake answering `update`.
    pub(crate) fn update(update: FirmwareUpdate) -> Self {
        Self {
            update: Some(update),
            faults: FaultInjection::default(),
            collector: false,
        }
    }

    /// The update check attached and `faults` injected into the fake router.
    pub(crate) const fn update_with_faults(update: FirmwareUpdate, faults: FaultInjection) -> Self {
        Self {
            update: Some(update),
            faults,
            collector: false,
        }
    }

    /// The log collector running.
    pub(crate) fn collector() -> Self {
        Self {
            update: None,
            faults: FaultInjection::default(),
            collector: true,
        }
    }

    /// The fake's `components check-update` answer, when the check is attached.
    pub(crate) fn firmware(&self) -> Option<FirmwareUpdate> {
        self.update.clone()
    }

    /// Failures injected into the fake router.
    pub(crate) fn faults(&self) -> FaultInjection {
        self.faults.clone()
    }

    /// Whether the log collector runs.
    pub(crate) const fn collects(&self) -> bool {
        self.collector
    }
}

/// Starts the log collector of `router` with the default `[logs]` settings.
pub(crate) async fn collector(registry: &RouterRegistry, router: &str) -> TestResult<LogService> {
    let config = Config::from_toml_str("[logs]\nenabled = true\n")?;
    config.validate()?;
    let client = registry.client(router).await?;
    Ok(LogService::start(
        vec![(router.to_owned(), client)],
        &config.logs,
        SelfMetrics::new("0.0.0-test")?,
    )
    .await?)
}

/// The response body as text.
pub(crate) async fn text(response: Response) -> TestResult<String> {
    let bytes = to_bytes(response.into_body(), 0x0040_0000).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

/// The `name=value` pair of the response's `Set-Cookie`.
pub(crate) fn cookie_pair(response: &Response) -> TestResult<String> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| "missing Set-Cookie".into())
}
