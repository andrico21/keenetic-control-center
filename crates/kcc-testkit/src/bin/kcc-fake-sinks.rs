//! `kcc-fake-sinks`: serves a [`FakeLoki`], a [`FakeElasticsearch`] and a [`FakeTelegram`]
//! (accepting any token) on loopback.
//!
//! Prints `loki <url>`, `elasticsearch <url>` and `telegram <url>` on stdout once all
//! listen, then reports every change of the captured request counts as a `sink requests`
//! line on stderr until Ctrl-C. `deploy/podman/e2e.sh` reads both streams.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{
    io::{self, Write as _},
    process::ExitCode,
};

use kcc_testkit::{
    fake_elasticsearch::FakeElasticsearch, fake_loki::FakeLoki, fake_telegram::FakeTelegram,
};
use tokio::{runtime::Builder, signal, time};

/// How often the captured request counts are compared.
const REPORT_EVERY: Duration = Duration::from_millis(250);

/// Logs the captured request counts whenever they change, until aborted or until it holds
/// the last handle.
// cancel-safe: holds no state outside the shared handles.
async fn report(loki: Arc<FakeLoki>, search: Arc<FakeElasticsearch>, telegram: Arc<FakeTelegram>) {
    let mut reported = (0_usize, 0_usize, 0_usize);
    let mut ticks = time::interval(REPORT_EVERY);
    while Arc::strong_count(&loki) > 1 {
        let _tick: time::Instant = ticks.tick().await;
        let now = (
            loki.requests().len(),
            search.requests().len(),
            telegram.requests().len(),
        );
        if now != reported {
            reported = now;
            tracing::info!(
                loki = now.0,
                elasticsearch = now.1,
                telegram = now.2,
                "sink requests"
            );
        }
    }
}

/// Starts the sinks, prints their URLs and reports request counts until Ctrl-C.
///
/// # Errors
///
/// Binding, stdout or shutdown errors.
// NOT cancel-safe: runs until the shutdown signal; meant as the top-level task.
async fn serve() -> Result<(), Box<dyn Error>> {
    let loki = Arc::new(FakeLoki::spawn().await?);
    let search = Arc::new(FakeElasticsearch::spawn().await?);
    let telegram = Arc::new(FakeTelegram::spawn().await?);
    {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "loki {}", loki.url())?;
        writeln!(stdout, "elasticsearch {}", search.url())?;
        writeln!(stdout, "telegram {}", telegram.url())?;
        stdout.flush()?;
    }
    let reporter = tokio::spawn(report(
        Arc::clone(&loki),
        Arc::clone(&search),
        Arc::clone(&telegram),
    ));
    let stopped = signal::ctrl_c().await;
    reporter.abort();
    drop(reporter.await);
    stopped?;
    match (
        Arc::try_unwrap(loki),
        Arc::try_unwrap(search),
        Arc::try_unwrap(telegram),
    ) {
        (Ok(loki_server), Ok(search_server), Ok(telegram_server)) => {
            loki_server.shutdown().await?;
            search_server.shutdown().await?;
            telegram_server.shutdown().await?;
            Ok(())
        }
        _ => Err("a sink handle is still shared after the reporter stopped".into()),
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_writer(io::stderr).init();
    let outcome = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Box::<dyn Error>::from)
        .and_then(|runtime| runtime.block_on(serve()));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "kcc-fake-sinks failed");
            ExitCode::FAILURE
        }
    }
}
