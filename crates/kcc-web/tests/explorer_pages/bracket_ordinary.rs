//! An ordinary write the router received is finished and audited when the browser leaves.
//!
//! The write's receipt waits on another process's audit append lock, the browser stops
//! waiting, and the write still ends: both its router receipt and the Web entry are
//! written once the lock is free.

use core::{pin::pin, time::Duration};

use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
use tokio::{
    sync::oneshot,
    time::{sleep, timeout},
};

use crate::{
    form,
    support::{Fixture, TestResult},
};

/// The CLI console's ordinary write.
const LINE: &str = "system country DE";

/// The browser leaves while the write's receipt waits; the write still ends and is
/// audited.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test(start_paused = true)]
async fn an_ordinary_write_is_audited_after_the_browser_leaves() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let lock = StateStore::open(&fixture.state_dir())?.try_lock(AUDIT_FILE_NAME)?;
    let (release, released) = oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        drop(released.await);
        drop(lock);
    });

    {
        let request = form(&[("line", LINE), ("confirm", "yes")]);
        let mut pending = pin!(fixture.post("/ui/r/home/console/cli/send", &browser, &request));
        assert!(
            timeout(Duration::from_secs(5), pending.as_mut())
                .await
                .is_err(),
            "still waiting on its receipt"
        );
        assert!(
            fixture
                .handle()
                .request_log()
                .iter()
                .any(|record| record.command() == Some(LINE)),
            "the router received the write"
        );
    }
    assert!(release.send(()).is_ok(), "the lock holder waits");
    holder.await?;
    sleep(Duration::from_secs(60)).await;

    let entries = fixture.audit()?;
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"router.change_cli"), "{actions:?}");
    assert!(actions.contains(&"web.console_cli"), "{actions:?}");
    Ok(())
}
