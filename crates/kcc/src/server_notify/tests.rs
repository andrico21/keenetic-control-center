//! The notifier in-process over a fake router and a fake Telegram.
//!
//! The tests run in real time with short poll intervals and delivery timings. A router
//! outage is a fake router stopped and served again on the same address.

use core::{error::Error, net::SocketAddr, time::Duration};

use kcc_app::{audit::AuditLog, notify_store::NotifyEvent, poller::PollResult, pseudonym};
use kcc_testkit::{Handle, fake_telegram::FakeTelegram};
use tempfile::TempDir;
use tokio::sync::watch;

use self::rig::{fake, fake_with_visitor};
use super::NotifyHandle;

mod rig;

/// Test result.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The router's id.
const ROUTER: &str = "home";

/// Upper bound of every wait.
const WAIT: Duration = Duration::from_secs(30);

/// The unregistered device that joins in the privacy test.
const VISITOR_MAC: &str = "02:00:00:00:20:01";

/// Its host name.
const VISITOR_NAME: &str = "visitor-phone";

/// Its address.
const VISITOR_IP: &str = "192.0.2.77";

/// A notifier over one fake router and a fake Telegram.
struct Rig {
    /// State and password file.
    _directory: TempDir,
    /// Where messages arrive.
    telegram: FakeTelegram,
    /// The router's address, kept across restarts.
    address: SocketAddr,
    /// The serving fake router, while it runs.
    router: Option<Handle>,
    /// This test's subscription to the router's results.
    results: watch::Receiver<Option<PollResult>>,
    /// The audit writer.
    audit: AuditLog,
    /// The notifier.
    notify: NotifyHandle,
}

/// How many of `texts` contain `needle`.
fn count(texts: &[String], needle: &str) -> usize {
    texts.iter().filter(|text| text.contains(needle)).count()
}

/// Todo 10: a router that stops answering and comes back produces exactly one offline
/// and one online message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_outage_sends_one_down_and_one_up() -> TestResult {
    let mut rig = Rig::start(&[NotifyEvent::RouterDownUp], fake()?).await?;
    rig.polls(2, true).await?;

    rig.stop_router().await?;
    rig.messages(1).await?;
    rig.serve_again(fake()?).await?;
    rig.messages(2).await?;
    rig.polls(3, true).await?;
    rig.notify.stop().await;

    let texts = rig.texts();
    assert_eq!(count(&texts, "is offline since"), 1, "{texts:?}");
    assert_eq!(count(&texts, "is back online"), 1, "{texts:?}");
    assert_eq!(texts.len(), 2, "{texts:?}");
    Ok(())
}

/// Todo 10: a `system reboot` kcc sent mutes the router's offline and online messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reboot_entry_mutes_down_and_up() -> TestResult {
    let mut rig = Rig::start(
        &[NotifyEvent::RouterDownUp, NotifyEvent::ChangeFailed],
        fake()?,
    )
    .await?;
    rig.polls(2, true).await?;
    rig.audit(
        ("router.change_cli_terminal", "system reboot"),
        "applied_state_unknown",
    )
    .await?;
    rig.audit(("router.change_cli", "interface Home"), "failed")
        .await?;
    rig.messages(1).await?;

    rig.stop_router().await?;
    rig.polls(3, false).await?;
    rig.serve_again(fake()?).await?;
    rig.polls(3, true).await?;
    rig.notify.stop().await;

    let texts = rig.texts();
    assert_eq!(count(&texts, "router.change_cli"), 1, "{texts:?}");
    assert_eq!(texts.len(), 1, "no offline or online message: {texts:?}");
    Ok(())
}

/// Todo 10: with client details off, a new unregistered device is named by its pseudonym
/// only: the message carries neither its MAC, nor its name, nor its address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_device_is_named_by_its_pseudonym_only() -> TestResult {
    let mut rig = Rig::start(&[NotifyEvent::NewDevice], fake()?).await?;
    rig.polls(2, true).await?;

    rig.stop_router().await?;
    rig.serve_again(fake_with_visitor()?).await?;
    rig.messages(1).await?;
    rig.notify.stop().await;

    let texts = rig.texts();
    let [text] = texts.as_slice() else {
        return Err(format!("one message expected: {texts:?}").into());
    };
    assert!(
        text.contains(&pseudonym::client(ROUTER, VISITOR_MAC)),
        "{text}"
    );
    for private in [
        VISITOR_MAC,
        VISITOR_NAME,
        VISITOR_IP,
        "02:00:00:00",
        "192.0.2.",
    ] {
        assert!(!text.contains(private), "{private} in {text}");
    }
    Ok(())
}
