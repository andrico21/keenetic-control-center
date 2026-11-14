//! Restoring a backup: the wizard link only where the wizard is served, and a raw restore
//! that refuses another model before anything is asked or sent.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    PAGE, backup_names,
    support::{
        outcome::TestResult,
        page::{en, form, html, text},
        web::{Fixture, ROUTER},
    },
    upload,
};

#[tokio::test]
async fn a_raw_restore_refuses_another_model_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let giga = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\nsystem\n description giga\n!\n";
    assert_eq!(
        upload(&fixture, &admin, ("giga.txt", giga.as_bytes()))
            .await?
            .status(),
        StatusCode::OK,
        "stored"
    );
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    let restore = format!("{PAGE}/backups/raw-restore?name={name}");
    let operator = fixture.login("operator").await?;
    assert_eq!(
        fixture.post(&restore, &operator, "").await?.status(),
        StatusCode::FORBIDDEN,
        "admin only"
    );
    let named = form(&[("confirm", "yes"), ("confirm_name", "home")]);
    let refused = text(fixture.post(&restore, &admin, &named).await?).await?;
    let mut args = FluentArgs::new();
    args.set("model", "KN-1010");
    args.set("router", "home");
    args.set("value", "KN-1811");
    let message = html(&tr(Locale::En, keys::WEB_CONFIG_RAW_MODEL, Some(&args)));
    assert!(refused.contains(&message), "names both models: {refused}");
    assert!(!refused.contains("confirm_name"), "asks nothing");
    assert!(
        !fixture
            .handle()
            .request_log()
            .iter()
            .any(|entry| entry.path().starts_with("/fui/")),
        "nothing uploaded"
    );
    assert!(
        !fixture.handle().startup_config_text().contains("giga"),
        "the saved configuration is unchanged"
    );
    assert!(
        fixture.audited("web.config_raw_restore", "hardware_mismatch")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn the_wizard_link_follows_the_served_routes() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let wizard = fixture.get("/ui/migrate", &admin).await?.status() != StatusCode::NOT_FOUND;
    drop(fixture.post(&format!("{PAGE}/backups"), &admin, "").await?);
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    let link = format!(
        "href=\"/ui/migrate?source=backup&#38;router=home&#38;backup={name}&#38;target=home\""
    );
    assert_eq!(page.contains(&link), wizard, "the link: {page}");
    assert_eq!(
        page.contains(&en(keys::WEB_CONFIG_WIZARD_MISSING)),
        !wizard,
        "the notice instead"
    );
    let reader = fixture.login("viewer").await?;
    let read = text(fixture.get(PAGE, &reader).await?).await?;
    assert!(
        !read.contains("/ui/migrate?") && !read.contains(&en(keys::WEB_CONFIG_WIZARD_MISSING)),
        "neither without Migrate"
    );
    Ok(())
}

#[tokio::test]
async fn a_backup_of_the_same_model_restores_raw_after_the_router_name() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(fixture.post(&format!("{PAGE}/backups"), &admin, "").await?);
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let name = backup_names(&page).into_iter().next().ok_or("one backup")?;
    let client = fixture.registry().client(ROUTER).await?;
    drop(
        client
            .parse("interface Bridge0 description later-change")
            .await?,
    );
    drop(client.parse("system configuration save").await?);
    let restore = format!("{PAGE}/backups/raw-restore?name={name}");
    let asked = text(fixture.post(&restore, &admin, "").await?).await?;
    assert!(
        asked.contains("name=\"confirm_name\""),
        "asks first: {asked}"
    );
    assert!(
        fixture
            .handle()
            .startup_config_text()
            .contains("later-change"),
        "nothing restored yet"
    );
    let named = form(&[("confirm", "yes"), ("confirm_name", "home")]);
    let done = text(fixture.post(&restore, &admin, &named).await?).await?;
    let trail: Vec<String> = fixture
        .audit()?
        .into_iter()
        .map(|entry| format!("{} {}", entry.action, entry.outcome))
        .collect();
    assert!(
        done.contains(&en(keys::WEB_CONFIG_RAW_DONE)),
        "restored: {done} {}",
        trail.join("; ")
    );
    assert!(
        !fixture
            .handle()
            .startup_config_text()
            .contains("later-change"),
        "the backup is the saved configuration again"
    );
    assert!(
        fixture.audited("web.config_raw_restore", "success")?,
        "audited"
    );
    Ok(())
}
