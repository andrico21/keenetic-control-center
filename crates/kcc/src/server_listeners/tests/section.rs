//! The serialized section: changes run one after the other in the order they were queued,
//! and a candidate planned on an older revision is refused before anything stops.

use std::fs;

use kcc_app::{
    mcp_settings::{commit, document::McpOverrides},
    persist::StateStore,
    settings::mcp_schema::Endpoint,
};
use reqwest::StatusCode;

use super::{
    TestResult, bounded,
    client::{http, session, tools},
    endpoint,
    fixture::{Fixture, Setup},
    holding,
};
use crate::server_listeners::{ListenerError, Restarted, supervisor::Stage};

/// A copy of `fixture`'s state files (no subdirectories) in a new directory.
fn copy_state(fixture: &Fixture) -> TestResult<(tempfile::TempDir, StateStore)> {
    let directory = tempfile::TempDir::new()?;
    for listed in fs::read_dir(fixture.state.dir())? {
        let entry = listed?;
        if !entry.file_type()?.is_dir() {
            let _: u64 = fs::copy(entry.path(), directory.path().join(entry.file_name()))?;
        }
    }
    let state = StateStore::open(directory.path())?;
    Ok((directory, state))
}

/// Todo 26: two restarts queued together run one after the other: the second, planned on
/// the revision the first saves, starts only once the first finished, and both apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_restarts_run_one_after_the_other() -> TestResult {
    let (hook, mut holds) = holding(&[Stage::Serving]);
    let fixture = Fixture::start(Setup {
        hook,
        ..Setup::default()
    })
    .await?;
    let first = fixture.plan(&endpoint(Endpoint::Both))?;
    let (_copy, ahead) = copy_state(&fixture)?;
    commit(&ahead, &first)?;
    let second = fixture.plan_on(&ahead, &endpoint(Endpoint::Main))?;

    let one = tokio::spawn(fixture.supervisor.restart(first));
    let two = tokio::spawn(fixture.supervisor.restart(second));
    let before_first = holds.until(Stage::Serving).await?;
    holds.release()?;
    let before_second = holds.until(Stage::Serving).await?;
    holds.release_all()?;

    assert!(matches!(bounded(one).await???, Restarted::Applied));
    assert!(matches!(bounded(two).await???, Restarted::Applied));
    assert_eq!(before_first, [Stage::Stopped]);
    assert_eq!(before_second, [Stage::Stopped]);
    assert_eq!(fixture.revision()?, 2);
    assert_eq!(fixture.saved()?.endpoint, Endpoint::Main);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: changes queued behind a restart held open wait for it.
///
/// A live change and another restart were planned on the revision the restart replaces,
/// so both are refused with `SettingsChanged` before anything stops, and
/// `mcp_settings.json` then holds the running settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_queued_behind_a_restart_wait_and_stale_ones_are_refused() -> TestResult {
    let (hook, mut holds) = holding(&[Stage::Serving]);
    let fixture = Fixture::start(Setup {
        hook,
        ..Setup::default()
    })
    .await?;
    let running = fixture.plan(&endpoint(Endpoint::Both))?;
    let mut read_only = McpOverrides::default();
    read_only.read_only = Some(true);
    let live_change = fixture.plan(&read_only)?;
    let stale_restart = fixture.plan(&endpoint(Endpoint::Main))?;

    let restart = tokio::spawn(fixture.supervisor.restart(running.clone()));
    let live = tokio::spawn(fixture.supervisor.apply_live(live_change));
    let stale = tokio::spawn(fixture.supervisor.restart(stale_restart));
    drop(holds.until(Stage::Serving).await?);
    holds.release_all()?;

    assert!(matches!(bounded(restart).await???, Restarted::Applied));
    assert!(matches!(
        bounded(live).await??,
        Err(ListenerError::SettingsChanged)
    ));
    assert!(matches!(
        bounded(stale).await??,
        Err(ListenerError::SettingsChanged)
    ));
    assert!(
        holds.reached.try_recv().is_err(),
        "a refused change stopped a listener"
    );
    assert_eq!(fixture.revision()?, 1);
    assert_eq!(&fixture.saved()?, running.effective().settings());
    assert_ne!(fixture.live.load().tool_specs(), []);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: `apply_live` applies a change that restarts nothing (new sessions see it) and
/// saves it; one that names a listener is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_live_applies_and_saves_without_a_restart() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let mut read_only = McpOverrides::default();
    read_only.read_only = Some(true);

    let refused = fixture
        .supervisor
        .apply_live(fixture.plan(&endpoint(Endpoint::Both))?)
        .await;
    fixture
        .supervisor
        .apply_live(fixture.plan(&read_only)?)
        .await?;

    assert!(
        matches!(refused, Err(ListenerError::RestartRequired)),
        "{refused:?}"
    );
    assert_eq!(fixture.revision()?, 1);
    assert!(fixture.saved()?.read_only);
    let client = http()?;
    let id = session(&client, fixture.main()?, &fixture.key).await?;
    let listed = tools(&client, (fixture.main()?, &fixture.key), &id).await?;
    assert!(
        !listed.iter().any(|name| name == "kcc_rci_delete"),
        "{listed:?}"
    );
    assert_eq!(
        fixture
            .supervisor
            .status()
            .main
            .ok_or("no main")?
            .generation,
        1
    );
    assert_eq!(
        super::client::status(&client, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    fixture.stop().await??;
    Ok(())
}
