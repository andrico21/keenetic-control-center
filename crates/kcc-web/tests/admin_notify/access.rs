//! Who may open the notifications page and what it shows.

extern crate alloc;

use alloc::sync::Arc;

use axum::http::{StatusCode, header};
use kcc_app::notify_store::{DisabledReason, NotifySettings, recipients::ChatId};
use kcc_i18n::keys;
use kcc_web::admin_notify::NotifyStatus;

use crate::{
    fixture::{Notify, Stub},
    support::{
        outcome::TestResult,
        page::{assert_native_post, en, header_text},
    },
};

const PAGE: &str = "/ui/admin/notifications";

/// Regression (todo 11): the page renders for an administrator and for a role holding
/// `ManageNotifications`, and an operator or a role without it gets 403 for the page and
/// its changes.
#[tokio::test]
async fn the_page_renders_only_for_roles_that_manage_notifications() -> TestResult {
    let fixture = Notify::build(None).await?;
    for allowed in ["admin", "nina"] {
        let browser = fixture.login(allowed).await?;
        let html = fixture.html(PAGE, &browser).await?;
        assert!(
            html.contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_NEW)),
            "{allowed} sees the token form"
        );
    }
    for refused in ["operator", "una"] {
        let browser = fixture.login(refused).await?;
        let page = fixture.get(PAGE, &browser).await?;
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{refused} page");
        let change = fixture.post(PAGE, &browser, &[("enabled", "on")]).await?;
        assert_eq!(change.status(), StatusCode::FORBIDDEN, "{refused} change");
    }
    assert!(
        fixture.store().read::<NotifySettings>()?.is_none(),
        "no refused change was stored"
    );
    Ok(())
}

/// Regression (todo 11): the token field is write-only and the Bot API address read-only.
///
/// The address is text from `kcc.toml` and no form field, every form posts natively as
/// well, and without a running notifier the page says changes apply at the next start.
#[tokio::test]
async fn the_page_shows_the_token_write_only_and_the_api_address_read_only() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(
        html.contains("name=\"token\" type=\"password\" value=\"\""),
        "an empty password field"
    );
    assert!(
        html.contains(">https://api.telegram.org/<"),
        "the default address as text"
    );
    assert!(!html.contains("name=\"api_url\""), "no address field");
    assert!(
        html.contains(&en(keys::WEB_ADMIN_NOTIFY_NEXT_START)),
        "changes apply at the next start"
    );
    assert!(
        html.contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_NONE)),
        "no token yet"
    );
    assert!(
        !html.contains("<script>") && !html.contains(" style="),
        "no inline script or style"
    );
    assert_native_post(&html)?;
    Ok(())
}

/// Regression (todo 11): the administration tab bar links the page only for a role that
/// may open it, and such a role lands on it from `/ui/admin`.
#[tokio::test]
async fn the_tab_shows_only_with_the_permission() -> TestResult {
    let fixture = Notify::build(None).await?;
    let link = format!("href=\"{PAGE}\"");
    let admin = fixture.login("admin").await?;
    assert!(
        fixture
            .html("/ui/admin/users", &admin)
            .await?
            .contains(&link),
        "the administrator's tab bar"
    );
    let una = fixture.login("una").await?;
    assert!(
        !fixture.html("/ui/admin/users", &una).await?.contains(&link),
        "no tab without ManageNotifications"
    );
    let nina = fixture.login("nina").await?;
    let landing = fixture.get("/ui/admin", &nina).await?;
    assert_eq!(
        header_text(&landing, header::LOCATION.as_str()).as_deref(),
        Some(PAGE),
        "the only administration page nina may open"
    );
    assert!(
        fixture.html(PAGE, &nina).await?.contains(&link),
        "nina's tab"
    );
    Ok(())
}

/// Regression (todo 11): a token Telegram refused shows an alert banner, and a chat it
/// refused shows why; the running notifier's queue is reported.
#[tokio::test]
async fn a_refused_token_and_a_refused_chat_are_shown() -> TestResult {
    let chat = ChatId::parse("-1009")?;
    let status = NotifyStatus::new(3, 2)
        .with_token_rejected()
        .with_disabled_chat(chat.clone(), DisabledReason::ChatNotFound);
    let fixture = Notify::build(Some(Stub::new(status, None))).await?;
    let admin = fixture.login("admin").await?;
    let added = fixture
        .post(
            "/ui/admin/notifications/chats",
            &admin,
            &[("id", chat.as_str()), ("label", "Ops")],
        )
        .await?;
    assert_eq!(added.status(), StatusCode::OK, "chat added");
    let html = fixture.html(PAGE, &admin).await?;
    let banner = format!(
        "role=\"alert\"><p class=\"banner__text\">{}",
        en(keys::WEB_ADMIN_NOTIFY_TOKEN_REJECTED)
    );
    assert!(html.contains(&banner), "the refused-token banner");
    assert!(
        html.contains(&en(keys::WEB_ADMIN_NOTIFY_CHAT_NOT_FOUND)),
        "the refused chat's reason"
    );
    assert!(
        html.contains(&en(keys::WEB_ADMIN_NOTIFY_RUNNING)),
        "the notifier runs"
    );
    assert!(
        !html.contains(&en(keys::WEB_ADMIN_NOTIFY_NEXT_START)),
        "no next-start notice"
    );
    Ok(())
}

/// Regression (todo 11): a stored change asks the running notifier to reload once.
#[tokio::test]
async fn the_page_reloads_the_attached_notifier_after_a_change() -> TestResult {
    let stub = Stub::new(NotifyStatus::default(), None);
    let fixture = Notify::build(Some(Arc::clone(&stub))).await?;
    let admin = fixture.login("admin").await?;
    let saved = fixture.post(PAGE, &admin, &[("enabled", "on")]).await?;
    assert_eq!(saved.status(), StatusCode::OK, "saved");
    assert_eq!(stub.reloads(), 1, "one reload per change");
    Ok(())
}
