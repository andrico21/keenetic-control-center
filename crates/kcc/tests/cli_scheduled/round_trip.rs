//! `kcc scheduled` add, list, show, edit, pause, resume and delete with `--json`.

use serde_json::{Value, json};

use crate::{
    DEFAULT_ZONE, ROUTER, audited, fixture, id_of, json_ok, listed,
    support::{Env, TestResult, USER},
};

/// Adds a backup on Monday and Wednesday at 03:30 in the default zone; answers its id.
fn add_backup(env: &Env) -> TestResult<String> {
    let added = json_ok(
        env,
        &[
            "--router",
            ROUTER,
            "scheduled",
            "add",
            "--name",
            "Nightly backup",
            "--days",
            "mon,wed",
            "--at",
            "03:30",
            "--backup",
        ],
    )?;
    assert_eq!(
        (
            added.pointer("/when/zone"),
            added.pointer("/when/days"),
            added.pointer("/when/hour"),
            added.pointer("/when/minute"),
        ),
        (
            Some(&json!(DEFAULT_ZONE)),
            Some(&json!(["mon", "wed"])),
            Some(&json!(3_u8)),
            Some(&json!(30_u8)),
        ),
        "{added}"
    );
    assert_eq!(
        added.get("owner"),
        Some(&json!({"kind": "cli", "os_user": USER})),
        "{added}"
    );
    assert_eq!(
        added.pointer("/state/state"),
        Some(&json!("active")),
        "{added}"
    );
    assert!(added.get("next_slot").is_some_and(Value::is_i64), "{added}");
    id_of(&added)
}

/// Renames schedule `id`, moves it to 04:05 in Berlin and checks the rest stayed.
fn edit_time(env: &Env, id: &str) -> TestResult {
    let edited = json_ok(
        env,
        &[
            "scheduled",
            "edit",
            id,
            "--name",
            "Weekly backup",
            "--at",
            "04:05",
            "--tz",
            "europe/berlin",
        ],
    )?;
    assert_eq!(
        (
            edited.get("name"),
            edited.pointer("/when/hour"),
            edited.pointer("/when/minute"),
            edited.pointer("/when/zone"),
            edited.pointer("/when/days"),
            edited.pointer("/action/kind"),
        ),
        (
            Some(&json!("Weekly backup")),
            Some(&json!(4_u8)),
            Some(&json!(5_u8)),
            Some(&json!("Europe/Berlin")),
            Some(&json!(["mon", "wed"])),
            Some(&json!("backup")),
        ),
        "{edited}"
    );
    Ok(())
}

/// Todo 16: add, list, show, edit, pause, resume and delete round trip with `--json`.
///
/// The zone defaults to `[schedules] default_timezone`; the owner is the CLI user; every
/// change is audited with the schedule id, the action kind and the router.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedules_round_trip_with_json() -> TestResult {
    let (env, handle) = fixture("admin").await?;
    let id = add_backup(&env)?;
    assert_eq!(listed(&env)?, vec![id.clone()]);
    let shown = json_ok(&env, &["scheduled", "show", &id])?;
    assert_eq!(shown.get("name"), Some(&json!("Nightly backup")));
    assert_eq!(shown.get("runs"), Some(&json!([])));

    edit_time(&env, &id)?;
    let paused = json_ok(&env, &["scheduled", "pause", &id])?;
    let resumed = json_ok(&env, &["scheduled", "resume", &id])?;
    let deleted = json_ok(&env, &["scheduled", "delete", &id])?;

    assert_eq!(
        (
            paused.pointer("/state/state"),
            paused.pointer("/state/reason")
        ),
        (Some(&json!("paused")), Some(&json!("manual")))
    );
    assert_eq!(paused.get("next_slot"), Some(&Value::Null));
    assert_eq!(resumed.pointer("/state/state"), Some(&json!("active")));
    assert_eq!(deleted, json!({"id": id, "deleted": true}));
    assert_eq!(listed(&env)?, Vec::<String>::new());
    let entries = audited(&env)?;
    let actions = entries
        .iter()
        .map(|entry| entry.get("action").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        [
            "cli.schedule_add",
            "cli.schedule_edit",
            "cli.schedule_pause",
            "cli.schedule_resume",
            "cli.schedule_delete",
        ]
        .map(Some)
    );
    for entry in &entries {
        assert_eq!(
            entry.get("params_redacted"),
            Some(&json!({"id": id, "action": "backup", "router": ROUTER})),
            "{entry}"
        );
    }
    handle.shutdown().await?;
    Ok(())
}
