//! The backup store behind the page: backups made in one second, a store that cannot be
//! read, and the delete dialog of a labelled router.

use std::fs;

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE, backup_names,
    support::{
        outcome::TestResult,
        page::{en, en_with, form, text},
        web::{Fixture, ROUTER},
    },
};

/// W2-06: backups created in the same second keep the reason they were made for; the
/// store names the second one itself (`<second>-1-manual.txt`), with no copy number
/// added to its reason.
#[tokio::test]
async fn backups_made_in_one_second_keep_their_reason() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    // Creates until two land in the same second (the first pair almost always does);
    // the bound only keeps a slow machine from looping.
    let mut seconds = Vec::new();
    for attempt in 1_u8..=10 {
        let created = fixture
            .post(&format!("{PAGE}/backups"), &operator, "")
            .await?;
        assert_eq!(created.status(), StatusCode::OK, "backup {attempt} created");
        seconds = fixture
            .backup_store()?
            .list(ROUTER)?
            .into_iter()
            .map(|info| (info.created_at, info.name, info.reason))
            .collect();
        let mut stamps: Vec<u64> = seconds.iter().map(|(at, _, _)| *at).collect();
        stamps.dedup();
        if stamps.len() < seconds.len() {
            break;
        }
    }
    let (second, _, _) = seconds
        .windows(2)
        .find_map(|pair| match pair {
            [newer, older] if newer.0 == older.0 => Some(newer.clone()),
            _ => None,
        })
        .ok_or("two backups in one second")?;
    assert!(
        seconds.iter().all(|(_, _, reason)| reason == "manual"),
        "every backup keeps its reason: {seconds:?}"
    );
    assert!(
        seconds
            .iter()
            .any(|(_, name, _)| *name == format!("{second}-1-manual.txt")),
        "the store names the second one: {seconds:?}"
    );
    Ok(())
}

/// W2-11: a backup store that cannot be listed stops a delete with the store's message,
/// audited `failed`, instead of an unaudited "not found".
#[tokio::test]
async fn a_store_that_cannot_be_listed_stops_a_delete() -> TestResult {
    let fixture = Fixture::new().await?;
    let backups = fixture.state_dir().join("backups");
    fs::create_dir_all(&backups)?;
    fs::write(backups.join(ROUTER), b"not a directory")?;
    let admin = fixture.login("admin").await?;
    let answer = fixture
        .post(
            &format!("{PAGE}/backups/delete?name=1700000000-manual.txt"),
            &admin,
            &format!("confirm=yes&confirm_name={ROUTER}"),
        )
        .await?;
    assert_eq!(answer.status(), StatusCode::OK, "answered in the outcome");
    let body = text(answer).await?;
    assert!(
        body.contains(&en(keys::WEB_CONFIG_STORE_FAILED)),
        "the store's message: {body}"
    );
    assert!(
        fixture.audited("web.config_backup_delete", "failed")?,
        "audited"
    );
    Ok(())
}

/// Todo 11: the delete dialog of a labelled router names it by its name and asks for its
/// id: the name typed back is refused and the backup stays, the id deletes it.
#[tokio::test]
async fn the_delete_dialog_names_the_router_and_asks_for_its_id() -> TestResult {
    let label = "Home Office";
    let fixture = Fixture::new().await?;
    fixture.label(ROUTER, label).await?;
    let admin = fixture.login("admin").await?;
    drop(fixture.post(&format!("{PAGE}/backups"), &admin, "").await?);
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    let delete = format!("{PAGE}/backups/delete?name={name}");
    let asked = text(fixture.post(&delete, &admin, "").await?).await?;
    let key = keys::WEB_CONFIG_DELETE_TEXT;
    let expected = en_with(key, &[("router", label), ("id", ROUTER)]);
    assert_ne!(
        expected,
        en_with(key, &[("router", label), ("id", label)]),
        "the text names the id to type"
    );
    assert!(
        asked.contains(&expected),
        "the dialog names the router and its id: {asked}"
    );
    let by_name = form(&[("confirm", "yes"), ("confirm_name", label)]);
    let refused = text(fixture.post(&delete, &admin, &by_name).await?).await?;
    assert!(
        refused.contains("name=\"confirm_name\"")
            && refused.contains(&en_with(
                keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
                &[("router", ROUTER)]
            )),
        "the name is not the id: {refused}"
    );
    let kept = text(fixture.get(PAGE, &admin).await?).await?;
    assert!(backup_names(&kept).contains(&name), "kept: {kept}");
    let by_id = form(&[("confirm", "yes"), ("confirm_name", ROUTER)]);
    let deleted = text(fixture.post(&delete, &admin, &by_id).await?).await?;
    assert!(
        deleted.contains(&en(keys::WEB_CONFIG_BACKUP_DELETED)),
        "the id passes the gate: {deleted}"
    );
    assert!(
        fixture.audited("web.config_backup_delete", "success")?,
        "audited"
    );
    Ok(())
}
