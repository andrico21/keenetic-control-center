//! What the router dashboard and the configuration page say about scheduled actions.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::schedules::{
    ledger::{RunLedger, RunOutcome, Trigger},
    model::{
        Action,
        names::{ClientMac, PolicyName},
    },
    time::{ZoneName, format_local},
};
use kcc_i18n::keys;
use kcc_rci::{RciBody, RciPath};

use crate::{
    fixture::Scheduled,
    stub::Stub,
    support::{outcome::TestResult, page::en_with},
};

/// Regression (todo 15): the dashboard names the router's next scheduled action, in the
/// schedule's zone, once the running scheduler reports one, to a role that may read the
/// router.
#[tokio::test]
async fn the_dashboard_names_the_next_scheduled_action() -> TestResult {
    let stub = Stub::new();
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let viewer = fixture.login("viewer").await?;
    let slot = 1_700_096_400;
    let line = en_with(
        keys::WEB_SCHEDULED_NEXT,
        &[
            ("name", "Nightly backup"),
            ("time", &format_local(slot, &ZoneName::parse("UTC")?)),
        ],
    );
    let before = fixture.html("/ui/r/home", &viewer).await?;
    assert!(!before.contains(&line), "nothing planned yet");
    drop(fixture.stored("Nightly backup", Action::Backup)?);
    stub.plan("home", "Nightly backup", slot);
    let after = fixture.html("/ui/r/home", &viewer).await?;
    assert!(after.contains(&line), "the next scheduled action: {after}");
    Ok(())
}

/// Regression (todo 15): the configuration page names the scheduled action whose change
/// the router reports unsaved, only while the router's checksum is the one the run
/// recorded.
#[tokio::test]
async fn the_configuration_page_names_an_unsaved_scheduled_change() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let action = Action::PolicySwitch {
        mac: ClientMac::parse("02:00:00:00:10:01")?,
        policy: PolicyName::parse("Policy0")?,
    };
    let schedule = fixture.stored("Kids offline", action)?;
    let client = fixture.web().registry().client("home").await?;
    drop(
        client
            .parse("interface Bridge0 description scheduled-change")
            .await?,
    );
    let path = RciPath::from_segments(["show", "last-change"])?;
    let RciBody::Json(answer) = client.show(&path, &()).await? else {
        return Err("last-change is not JSON".into());
    };
    let checksum = answer
        .value
        .get("checksum")
        .and_then(|value| value.as_str())
        .ok_or("no checksum")?
        .to_owned();
    let ledger = RunLedger::new(fixture.store().clone());
    let finished = |recorded: String, at: i64| -> TestResult {
        let requested_by = "web:admin".to_owned();
        let began = ledger.begin(&schedule.id, Trigger::Now { requested_by }, at)?;
        let done = RunOutcome::Succeeded {
            unsaved: true,
            checksum: Some(recorded),
        };
        Ok(ledger.finish(&schedule.id, began, done, None, at)?)
    };
    let note = |at: i64| -> TestResult<String> {
        Ok(en_with(
            keys::WEB_SCHEDULED_UNSAVED,
            &[
                ("name", "Kids offline"),
                ("time", &format_local(at, &ZoneName::parse("UTC")?)),
            ],
        ))
    };
    let admin = fixture.login("admin").await?;
    finished("0".repeat(checksum.len()), 1_700_000_100)?;
    let other = fixture.html("/ui/r/home/config", &admin).await?;
    assert!(
        !other.contains(&note(1_700_000_100)?),
        "another checksum: no note"
    );
    finished(checksum, 1_700_000_200)?;
    let page = fixture.html("/ui/r/home/config", &admin).await?;
    assert!(page.contains(&note(1_700_000_200)?), "the note: {page}");
    Ok(())
}
