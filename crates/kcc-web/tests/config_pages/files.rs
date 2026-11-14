//! Backups as files: uploaded, compared as exactly their changed lines, downloaded with
//! or without their secrets, and deleted behind the typed router name.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    PAGE, backup_names, changed,
    safety::change_and_arm,
    support::{
        outcome::TestResult,
        page::{en, header_text, html, text},
        typed_name::{Ask, TypedName, typed_names},
        web::Fixture,
    },
    upload,
};

/// The older of the two compared configurations.
const OLD: &str = "! $$$ Model: KN-1811\nsystem\n description alpha\n!\n\
                   interface Bridge0\n description home\n mtu 1500\n!\n\
                   ip name-server 192.0.2.53\n!\n";

/// The newer one: one description changed, one server gone, one line added.
const NEW: &str = "! $$$ Model: KN-1811\nsystem\n description alpha\n!\n\
                   interface Bridge0\n description office\n mtu 1500\n!\n\
                   ntp server pool.example\n!\n";

#[tokio::test]
async fn two_backups_compare_as_exactly_their_changed_lines() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    for (name, file) in [("old.txt", OLD), ("new.txt", NEW)] {
        let stored = upload(&fixture, &operator, (name, file.as_bytes())).await?;
        assert_eq!(stored.status(), StatusCode::OK, "{name} stored");
    }
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    let names = backup_names(&page);
    let (Some(old), Some(new)) = (
        names.iter().find(|name| name.ends_with("-upload-old.txt")),
        names.iter().find(|name| name.ends_with("-upload-new.txt")),
    ) else {
        return Err(format!("both uploads listed: {names:?}").into());
    };
    assert!(
        page.contains(">old<") && page.contains(">new<"),
        "file names"
    );
    for view in ["unified", "split"] {
        let path = format!("{PAGE}/diff?from={old}&to={new}&view={view}");
        let diff = text(fixture.get(&path, &operator).await?).await?;
        assert_eq!(
            changed(&diff, "removed"),
            [
                "interface Bridge0 description home",
                "ip name-server 192.0.2.53"
            ],
            "{view}: removed"
        );
        assert_eq!(
            changed(&diff, "added"),
            [
                "interface Bridge0 description office",
                "ntp server pool.example"
            ],
            "{view}: added"
        );
        assert!(
            !diff.contains("description alpha"),
            "{view}: no unchanged line"
        );
    }
    let running = format!("{PAGE}/diff?from={old}&to=running");
    let against = text(fixture.get(&running, &operator).await?).await?;
    assert!(
        changed(&against, "added")
            .contains(&html("interface Bridge0 description \"Home network\"")),
        "the running configuration's own lines: {against}"
    );
    Ok(())
}

#[tokio::test]
async fn uploads_of_one_file_in_one_second_are_all_kept() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    for attempt in 1_u8..=3 {
        let stored = upload(&fixture, &operator, ("same.txt", OLD.as_bytes())).await?;
        assert_eq!(stored.status(), StatusCode::OK, "upload {attempt} stored");
    }
    assert_eq!(fixture.backups()?, 3, "none replaced or refused");
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    assert_eq!(
        page.matches("<span class=\"mono\">same</span>").count(),
        3,
        "each listed as the upload of same.txt: {page}"
    );
    Ok(())
}

#[tokio::test]
async fn only_reveal_secrets_downloads_the_ns3_blobs() -> TestResult {
    let fixture = Fixture::new().await?;
    let blob = "QUJD".repeat(8);
    let file = format!(
        "! $$$ Model: KN-1811\ninterface WifiMaster0/AccessPoint0\n authentication wpa-psk ns3 {blob}\n!\n\
         system\n description lab\n!\n"
    );
    let operator = fixture.login("operator").await?;
    assert_eq!(
        upload(&fixture, &operator, ("lab.txt", file.as_bytes()))
            .await?
            .status(),
        StatusCode::OK,
        "stored"
    );
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    let download = format!("{PAGE}/backups/download?name={name}");
    let redacted = fixture.get(&download, &operator).await?;
    assert_eq!(redacted.status(), StatusCode::OK, "redacted");
    assert!(
        header_text(&redacted, "content-disposition")
            .is_some_and(|value| value.contains("-redacted.txt")),
        "named as redacted"
    );
    let copy = text(redacted).await?;
    assert!(
        copy.contains("system\n description lab"),
        "settings: {copy}"
    );
    assert!(
        !copy.contains("ns3 ") && !copy.contains(&blob),
        "no ns3 blob: {copy}"
    );
    let refused = fixture
        .get(&format!("{download}&full=yes"), &operator)
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "RevealSecrets");
    let admin = fixture.login("admin").await?;
    let full = text(fixture.get(&format!("{download}&full=yes"), &admin).await?).await?;
    assert!(full.contains(&format!("ns3 {blob}")), "as stored: {full}");
    assert!(
        fixture.audited("web.config_backup_download", "success")?,
        "audited"
    );
    let log = serde_json::to_string(&fixture.audit()?)?;
    assert!(
        !log.contains(&blob) && !log.contains("description lab"),
        "no value audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_file_that_is_not_a_configuration_is_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let png = [
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe,
    ];
    let binary = upload(&fixture, &operator, ("photo.png", &png)).await?;
    assert_eq!(binary.status(), StatusCode::UNPROCESSABLE_ENTITY, "binary");
    assert_eq!(
        header_text(&binary, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back in the dialog"
    );
    let shown = text(binary).await?;
    assert!(
        shown.contains(&en(keys::WEB_CONFIG_UPLOAD_NOT_TEXT)),
        "parse error: {shown}"
    );
    let mut args = FluentArgs::new();
    args.set("line", 3_u8);
    let skewed = upload(
        &fixture,
        &operator,
        ("bad.txt", b"interface Bridge0\n  description x\n   up\n"),
    )
    .await?;
    assert_eq!(
        skewed.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "indentation"
    );
    let line = html(&tr(Locale::En, keys::WEB_CONFIG_UPLOAD_PARSE, Some(&args)));
    assert!(text(skewed).await?.contains(&line), "names the line");
    let large = vec![b'!'; 0x0010_0001];
    let oversized = upload(&fixture, &operator, ("big.txt", &large)).await?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE, "1 MiB");
    assert!(
        text(oversized)
            .await?
            .contains(&en(keys::WEB_CONFIG_UPLOAD_TOO_LARGE)),
        "size error"
    );
    assert_eq!(fixture.backups()?, 0, "nothing stored");
    assert!(
        fixture.audited("web.config_backup_upload", "not_config")?,
        "audited"
    );
    Ok(())
}

/// A backup delete and a rollback need the router's name.
#[tokio::test]
async fn typed_names_are_exact() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let created = text(fixture.post(&format!("{PAGE}/backups"), &admin, "").await?).await?;
    assert!(
        created.contains(&en(keys::WEB_CONFIG_BACKUP_CREATED)),
        "created: {created}"
    );
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    change_and_arm(&fixture, "rolled-change").await?;
    let (delete, rollback) = (
        format!("{PAGE}/backups/delete?name={name}"),
        format!("{PAGE}/rollback"),
    );
    drop(
        typed_names(
            &fixture,
            &[
                TypedName {
                    action: "web.config_backup_delete",
                    account: "admin",
                    denied: Some("operator"),
                    ask: Ask::Post(&delete, ""),
                    title: None,
                    post: &delete,
                    fields: &[],
                    names: ("HOME", "home"),
                    ran: ("success", keys::WEB_CONFIG_BACKUP_DELETED),
                    rereads: false,
                },
                TypedName {
                    action: "web.config_rollback",
                    account: "admin",
                    denied: Some("operator"),
                    ask: Ask::Post(&rollback, ""),
                    title: None,
                    post: &rollback,
                    fields: &[],
                    names: ("Home", "home"),
                    ran: ("success", keys::WEB_KIT_DONE_TERMINAL),
                    rereads: true,
                },
            ],
        )
        .await?,
    );
    let after = text(fixture.get(PAGE, &admin).await?).await?;
    assert!(!backup_names(&after).contains(&name), "gone: {after}");
    let running = fixture.handle().running_config_text();
    assert!(!running.contains("rolled-change"), "the saved one is back");
    Ok(())
}
