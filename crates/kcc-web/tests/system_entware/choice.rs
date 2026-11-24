//! The drive of the setup is the user's choice: the form checks no radio, a setup without
//! a drive is refused before anything reaches the router, and the internal storage is used
//! only when it is chosen.

use kcc_i18n::keys;
use kcc_testkit::FakeRouterBuilder;
use serde_json::json;

use super::{
    DRIVE, PAGE, heard, heard_since, mark, over, ready,
    setup::{AARCH64_URL, followed},
};
use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
};

/// A ready KN-1811 whose only medium is NTFS, so no drive is eligible for Entware.
fn no_eligible_drive() -> FakeRouterBuilder {
    let media = json!([{
        "id": "Media0", "label": "fixture-media",
        "uuid": "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0", "filesystem": "ntfs",
        "size": 8_000_000_000_u64, "free": 6_000_000_000_u64,
        "initialize-supported": ["default", "ext4", "ntfs"],
    }]);
    ready().show_fixture("media", media)
}

/// The opening tags of the setup form's drive radios on `page`.
fn drive_radios(page: &str) -> Vec<&str> {
    page.split("<input")
        .skip(1)
        .filter_map(|tail| tail.split_once('>').map(|(tag, _)| tag))
        .filter(|tag| tag.contains("name=\"drive\""))
        .collect()
}

/// Todo 34: with no eligible drive the form offers only the internal storage, unchecked,
/// with the router's UBIFS warning beside it.
#[tokio::test]
async fn the_internal_storage_alone_is_not_preselected() -> TestResult {
    let fixture = over(no_eligible_drive()).await?;
    let admin = fixture.login("admin").await?;
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let radios = drive_radios(&page);
    assert_eq!(radios.len(), 1, "{page}");
    let internal = radios.first().ok_or("no radio")?;
    assert!(
        internal.contains("id=\"entware-drive-internal\""),
        "{internal}"
    );
    assert!(!internal.contains(" checked"), "{internal}");
    assert!(
        internal.contains("aria-describedby=\"entware-internal-help\""),
        "{internal}"
    );
    let warning = format!(
        "id=\"entware-internal-help\">{}</p>",
        en(keys::WEB_SYSTEM_ENTWARE_INTERNAL_WARNING)
    );
    assert!(page.contains(&warning), "{page}");
    Ok(())
}

/// Todo 34: a single eligible drive is not chosen for the user either.
#[tokio::test]
async fn a_single_eligible_drive_is_not_preselected() -> TestResult {
    let fixture = over(ready()).await?;
    let admin = fixture.login("admin").await?;
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let radios = drive_radios(&page);
    assert_eq!(radios.len(), 2, "{page}");
    assert!(
        radios
            .iter()
            .any(|tag| tag.contains(&format!("value=\"{DRIVE}\""))),
        "{page}"
    );
    for tag in radios {
        assert!(!tag.contains(" checked"), "{tag}");
    }
    Ok(())
}

/// Todo 34: a confirmed setup without a drive, or with an empty one, is refused in the
/// user's words; after the page the form came from, the router hears nothing, not even a
/// read.
#[tokio::test]
async fn a_setup_without_a_drive_reaches_nothing() -> TestResult {
    let fixture = over(no_eligible_drive()).await?;
    let admin = fixture.login("admin").await?;
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    assert!(page.contains("id=\"entware-setup-form\""), "{page}");
    let path = format!("{PAGE}/setup");
    let confirmed = [("confirm", "yes"), ("confirm_name", "home")];
    let emptied = [("drive", ""), ("confirm", "yes"), ("confirm_name", "home")];
    for sent in [form(&confirmed), form(&emptied)] {
        let before = mark(&fixture);
        let body = text(fixture.post(&path, &admin, &sent).await?).await?;
        assert!(
            body.contains(&en(keys::WEB_SYSTEM_ENTWARE_DRIVE_NOT_ELIGIBLE)),
            "{sent}: {body}"
        );
        assert_eq!(mark(&fixture), before, "{sent}: nothing read or sent");
    }
    assert!(!heard(&fixture, "opkg disk"), "nothing installed");
    assert_eq!(
        fixture.outcomes("web.entware_setup")?,
        ["validation_failed", "validation_failed"]
    );
    Ok(())
}

/// Todo 34: the internal storage chosen explicitly asks for the router name, then installs
/// on `storage:/`.
#[tokio::test(start_paused = true)]
async fn the_internal_storage_chosen_installs_there() -> TestResult {
    let fixture = over(no_eligible_drive()).await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/setup");
    let before = mark(&fixture);
    let asked = text(
        fixture
            .post(&path, &admin, &form(&[("drive", "internal")]))
            .await?,
    )
    .await?;
    assert!(
        asked.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "{asked}"
    );
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent before the router name"
    );
    let confirmed = [
        ("drive", "internal"),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ];
    let panel = text(fixture.post(&path, &admin, &form(&confirmed)).await?).await?;
    let stream = panel
        .split_once("sse-connect=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(url, _)| url.to_owned())
        .ok_or("no job stream")?;
    let received = followed(&fixture, &admin, &stream).await?;
    assert!(
        received.contains(&en(keys::WEB_SYSTEM_ENTWARE_STEP_DONE)),
        "{received}"
    );
    assert!(heard(
        &fixture,
        &format!("opkg disk storage:/ {AARCH64_URL}")
    ));
    Ok(())
}
