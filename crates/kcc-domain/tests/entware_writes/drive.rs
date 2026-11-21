//! The Entware drive guard, `media initialize` and the wait for its ext4 partition.

use core::time::Duration;

use kcc_app::{permissions::Permission, workflow::WorkflowError};
use kcc_catalog::Risk;
use kcc_domain::{DomainError, entware, storage, verification};
use kcc_testkit::{FaultInjection, model::Firmware};
use serde_json::json;
use tokio::time::Instant;

use crate::{
    heard, operator,
    support::{Fixture, PROFILES, TestResult, administrator, refused_by_catalog},
};

/// The uuid of the fake router's synthetic `Media0`.
const MEDIA0_UUID: &str = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0";

/// Todo 4: the drive Entware runs from is resolved from `opkg disk` by uuid, then by a
/// label only one medium carries.
///
/// An unset disk, internal storage (even beside a medium labelled `storage`), an ambiguous
/// label or uuid and an unknown drive resolve to none.
#[tokio::test]
async fn configured_media_resolves_the_entware_drive() -> TestResult {
    let media = json!([
        {"id":"Media0","label":"fixture-media","uuid":MEDIA0_UUID,"filesystem":"ext4"},
        {"id":"Media1","label":"twin","uuid":"aaaa-1111","filesystem":"ext4"},
        {"id":"Media2","label":"twin","uuid":"bbbb-2222","filesystem":"ext4"},
        {"id":"Media3","label":"bbbb-2222","filesystem":"ext4"},
        {"label":"orphan","uuid":"cccc-3333","filesystem":"ext4"},
        {"id":"Media4","label":"storage","filesystem":"ext4"},
        {"id":"Media5","uuid":"dddd-4444","filesystem":"ext4"},
        {"id":"Media6","uuid":"dddd-4444","filesystem":"ext4"}
    ]);
    let upper = format!("{}:/", MEDIA0_UUID.to_ascii_uppercase());
    let rows: [(Option<&str>, Option<&str>); 11] = [
        (None, None),
        (Some("fixture-media:/"), Some("Media0")),
        (Some("fixture-media:/opt"), Some("Media0")),
        (Some(upper.as_str()), Some("Media0")),
        (Some("bbbb-2222:/"), Some("Media2")),
        (Some("twin:/"), None),
        (Some("storage:/"), None),
        (Some("unknown-drive:/"), None),
        (Some("orphan:/"), None),
        (Some("cccc-3333:/"), None),
        (Some("dddd-4444:/"), None),
    ];
    for firmware in PROFILES {
        for (disk, expected) in rows {
            let fixture = Fixture::spawn_with_show(firmware, [("media", media.clone())]).await?;
            if let Some(word) = disk {
                assert!(
                    fixture.handle().configure(&format!("opkg disk {word}")),
                    "{word}"
                );
            }

            let resolved = entware::configured_media(fixture.context()).await?;

            assert_eq!(resolved.as_deref(), expected, "{firmware} {disk:?}");
            fixture.shutdown().await?;
        }
    }
    Ok(())
}

/// Todo 4: ejecting or initializing the drive Entware runs from (named in `opkg disk` by
/// its label or by its uuid) is refused until acknowledged; other drives are not guarded.
#[tokio::test]
async fn the_entware_drive_is_guarded_until_acknowledged() -> TestResult {
    for disk in ["fixture-media:/".to_owned(), format!("{MEDIA0_UUID}:/")] {
        let fixture = Fixture::spawn(Firmware::V5_1).await?;
        assert!(fixture.handle().configure(&format!("opkg disk {disk}")));
        let ctx = fixture.context();
        let role = administrator();
        let entware = entware::configured_media(ctx).await?;
        assert_eq!(entware.as_deref(), Some("Media0"), "{disk}");
        let used = entware.as_deref();
        let before = fixture.handle().request_log().len();

        let eject = storage::plan_eject(ctx, "router", &role, "Media0", true, used, false);
        let initialize =
            storage::plan_initialize(ctx, "router", &role, "Media0", true, used, false);

        assert!(
            matches!(eject, Err(DomainError::EntwareDriveInUse)),
            "{disk}: {eject:?}"
        );
        assert!(
            matches!(initialize, Err(DomainError::EntwareDriveInUse)),
            "{disk}: {initialize:?}"
        );
        assert_eq!(fixture.handle().request_log().len(), before);
        drop(storage::plan_eject(
            ctx, "router", &role, "Media0", true, used, true,
        )?);
        drop(storage::plan_initialize(
            ctx, "router", &role, "Media0", true, used, true,
        )?);
        drop(storage::plan_eject(
            ctx, "router", &role, "Media1", true, used, false,
        )?);
        drop(storage::plan_initialize(
            ctx, "router", &role, "Media1", true, used, false,
        )?);
        drop(storage::plan_eject(
            ctx, "router", &role, "Media0", true, None, false,
        )?);
        drop(storage::plan_initialize(
            ctx, "router", &role, "Media0", true, None, false,
        )?);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Todo 4: `media initialize` is refused on firmware whose catalog lacks it, for a medium
/// that is not one CLI word, without confirmation and without `Destructive`.
#[tokio::test]
async fn initialize_refusals_happen_before_any_request() -> TestResult {
    for firmware in [Firmware::V4_3, Firmware::V5_0] {
        let fixture = Fixture::spawn(firmware).await?;
        let planned = storage::plan_initialize(
            fixture.context(),
            "router",
            &administrator(),
            "Media0",
            true,
            None,
            false,
        );
        assert!(refused_by_catalog(&planned), "{firmware}: {planned:?}");
        fixture.shutdown().await?;
    }
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let ctx = fixture.context();
    let before = fixture.handle().request_log().len();
    let admin = administrator();
    assert!(matches!(
        storage::plan_initialize(ctx, "router", &admin, "Media 0", true, None, false),
        Err(DomainError::InvalidCliToken)
    ));
    assert!(matches!(
        storage::plan_initialize(ctx, "router", &admin, "Media0", false, None, false),
        Err(DomainError::ConfirmationRequired)
    ));
    assert!(matches!(
        storage::plan_initialize(ctx, "router", &operator(), "Media0", true, None, false),
        Err(DomainError::PermissionDenied)
    ));
    assert_eq!(fixture.handle().request_log().len(), before);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 4: `media <name> initialize ext4` is a documented action without read-back; the
/// fake router hears exactly that line.
#[tokio::test]
async fn initialize_sends_its_line() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let plan = storage::plan_initialize(
        fixture.context(),
        "router",
        &administrator(),
        "Media0",
        true,
        None,
        false,
    )?;
    assert_eq!(
        (plan.risk, plan.permission),
        (Risk::Destructive, Permission::Destructive)
    );
    let request = storage::change_request(&plan)?;
    verification::require(&request)?;
    let mut changes = fixture.changes().await?;

    let outcome = changes.apply_cli(request).await;

    drop(changes);
    drop(outcome?);
    assert!(heard(&fixture, "media Media0 initialize ext4"));
    fixture.shutdown().await?;
    Ok(())
}

/// The number of `show media` reads the fake router answered.
fn media_reads(fixture: &Fixture) -> usize {
    fixture
        .handle()
        .request_log()
        .iter()
        .filter(|record| record.path().ends_with("show/media"))
        .count()
}

/// Todo 4: after `media initialize` the wait polls `show media` at its interval until the
/// medium reports ext4, which the fake does on the third read.
#[tokio::test(start_paused = true)]
async fn wait_initialized_returns_once_the_medium_is_ext4() -> TestResult {
    let fixture = Fixture::spawn_local(Firmware::V5_1).await?;
    drop(
        fixture
            .context()
            .client
            .parse("media Media0 initialize ext4")
            .await?,
    );
    let reads = media_reads(&fixture);
    let started = Instant::now();

    storage::wait_initialized(fixture.context(), "Media0").await?;

    assert_eq!(media_reads(&fixture) - reads, 3);
    assert_eq!(started.elapsed(), storage::INITIALIZE_POLL * 2);
    assert!(storage::INITIALIZE_POLL >= Duration::from_secs(1));
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 4: a `show media` read that fails during the wait ends it with that read's error
/// at once; it is neither retried nor turned into the ten-minute timeout.
#[tokio::test]
async fn wait_initialized_propagates_a_failed_media_read() -> TestResult {
    let faults = FaultInjection::default().fail_read_matching("show/media", 2);
    let fixture = Fixture::spawn_with_faults(Firmware::V5_1, faults).await?;
    drop(
        fixture
            .context()
            .client
            .parse("media Media0 initialize ext4")
            .await?,
    );
    let reads = media_reads(&fixture);

    let outcome = storage::wait_initialized(fixture.context(), "Media0").await;

    assert!(matches!(&outcome, Err(DomainError::Rci(_))), "{outcome:?}");
    assert_eq!(media_reads(&fixture) - reads, 1);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 4: a medium that never reports ext4 fails the wait after ten minutes with a
/// verification error naming the medium.
#[tokio::test(start_paused = true)]
async fn wait_initialized_gives_up_after_ten_minutes() -> TestResult {
    let fixture = Fixture::spawn_local(Firmware::V5_1).await?;
    let started = Instant::now();

    let outcome = storage::wait_initialized(fixture.context(), "Media7").await;

    assert!(
        matches!(&outcome, Err(DomainError::Workflow(WorkflowError::VerificationFailed { field })) if field.contains("Media7")),
        "{outcome:?}"
    );
    assert_eq!(storage::INITIALIZE_LIMIT, Duration::from_mins(10));
    assert!(started.elapsed() >= storage::INITIALIZE_LIMIT);
    assert!(started.elapsed() < storage::INITIALIZE_LIMIT + storage::INITIALIZE_POLL);
    fixture.shutdown().await?;
    Ok(())
}
