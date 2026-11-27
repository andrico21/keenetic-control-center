//! The idle task retires a router's channel only while nobody is subscribed.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]

use core::error::Error;

use tempfile::TempDir;
use tokio::sync::watch;

use super::{Arc, PollError, Poller};
use crate::{persist::StateStore, registry::RouterRegistry, settings::OutboundConfig};

/// B-17: a subscriber that arrives after the idle task decided to exit but before it
/// removed the entry keeps the entry, and still receives the router's next result.
#[tokio::test]
async fn a_late_subscriber_keeps_the_channel_entry() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let state = StateStore::open(directory.path())?;
    let registry = Arc::new(RouterRegistry::new(state, &[], &OutboundConfig::default())?);
    let poller = Poller::new(registry);
    let (sender, idle) = watch::channel(None);
    drop(idle);
    drop(
        poller
            .channels
            .lock()
            .await
            .insert("router".to_owned(), sender),
    );

    // The idle task saw no receiver; this subscriber arrives before it removes the entry.
    let mut late = poller
        .channels
        .lock()
        .await
        .get("router")
        .map(watch::Sender::subscribe)
        .ok_or("entry present")?;

    let retired = poller.retire("router").await;

    assert!(!retired, "an entry with a live receiver is not retired");
    let channels = poller.channels.lock().await;
    let kept = channels.get("router").ok_or("entry kept")?;
    kept.send(Some(Err(PollError::request("test"))))?;
    drop(channels);
    late.changed().await?;
    assert!(late.borrow().is_some(), "the late subscriber gets data");
    Ok(())
}

/// An entry nobody listens to is retired.
#[tokio::test]
async fn an_unwatched_entry_is_retired() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let state = StateStore::open(directory.path())?;
    let registry = Arc::new(RouterRegistry::new(state, &[], &OutboundConfig::default())?);
    let poller = Poller::new(registry);
    let (sender, idle) = watch::channel(None);
    drop(idle);
    drop(
        poller
            .channels
            .lock()
            .await
            .insert("router".to_owned(), sender),
    );

    assert!(poller.retire("router").await);
    assert!(poller.channels.lock().await.get("router").is_none());
    Ok(())
}
