//! The settings, the chats and the test message, and the CSRF guard on every change.

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};

use axum::http::StatusCode;
use kcc_app::notify_store::{NotifyEvent, NotifySettings};
use kcc_i18n::{keys, locale::Locale};
use kcc_web::admin_notify::{NotifyStatus, NotifyTestError};
use serde_json::json;

use crate::{
    fixture::{Notify, Stub},
    support::{
        outcome::TestResult,
        page::{en, text},
    },
};

const PAGE: &str = "/ui/admin/notifications";
const CHATS: &str = "/ui/admin/notifications/chats";
const REMOVE: &str = "/ui/admin/notifications/chats/remove";
const TEST: &str = "/ui/admin/notifications/test";

/// The stored settings, the defaults when none are stored.
fn settings(fixture: &Notify) -> TestResult<NotifySettings> {
    Ok(fixture
        .store()
        .read::<NotifySettings>()?
        .unwrap_or_default())
}

/// Regression (todo 11): the switches, the language and the ticked events are stored as
/// submitted, an unticked event is off, and an unknown event or language is refused.
#[tokio::test]
async fn settings_and_event_toggles_persist() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    let saved = fixture
        .post(
            PAGE,
            &admin,
            &[
                ("enabled", "on"),
                ("locale", "de"),
                ("client_details", "on"),
                ("events", "new_device"),
                ("events", "job_failed"),
            ],
        )
        .await?;
    assert_eq!(saved.status(), StatusCode::OK, "saved");
    assert!(
        text(saved)
            .await?
            .contains(&en(keys::WEB_ADMIN_NOTIFY_SETTINGS_SAVED)),
        "settings saved"
    );
    let stored = settings(&fixture)?;
    assert!(
        stored.enabled && stored.include_client_details,
        "switches on"
    );
    assert_eq!(stored.locale, Some(Locale::De), "language");
    assert_eq!(
        stored.events,
        BTreeSet::from([NotifyEvent::NewDevice, NotifyEvent::JobFailed]),
        "exactly the ticked events"
    );
    let html = fixture.html(PAGE, &admin).await?;
    assert!(
        html.contains("value=\"new_device\" checked"),
        "ticked on the page"
    );
    assert!(
        !html.contains("value=\"router_down_up\" checked"),
        "unticked"
    );

    let cleared = fixture.post(PAGE, &admin, &[("locale", "")]).await?;
    assert_eq!(cleared.status(), StatusCode::OK, "saved again");
    let off = settings(&fixture)?;
    assert!(
        !off.enabled && off.events.is_empty() && off.locale.is_none(),
        "all off"
    );
    for (field, value) in [("events", "carrier_pigeon"), ("locale", "xx")] {
        let refused = fixture.post(PAGE, &admin, &[(field, value)]).await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field}"
        );
    }
    assert_eq!(settings(&fixture)?, off, "refused forms change nothing");
    let audited = fixture.audited("web.notify_settings").await?;
    assert_eq!(audited.len(), 2, "two changes audited");
    Ok(())
}

/// Regression (todo 11): a chat is added with its topic and sound setting and removed
/// again; the audit names its label only, never its id.
#[tokio::test]
async fn chats_are_added_and_removed() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    let id = format!("-100{}", 3_u64.pow(20));
    let added = fixture
        .post(
            CHATS,
            &admin,
            &[
                ("id", &id),
                ("label", "Ops <team>"),
                ("thread", "7"),
                ("silent", "on"),
            ],
        )
        .await?;
    assert_eq!(added.status(), StatusCode::OK, "added");
    let stored = settings(&fixture)?;
    let chat = stored.chats.as_slice().first().ok_or("no chat")?;
    assert_eq!(
        (
            chat.id.as_str(),
            chat.label.as_str(),
            chat.thread,
            chat.silent
        ),
        (id.as_str(), "Ops <team>", Some(7), true),
        "the stored chat"
    );
    let html = fixture.html(PAGE, &admin).await?;
    assert!(html.contains("Ops &#60;team&#62;"), "the escaped label");
    let again = fixture
        .post(CHATS, &admin, &[("id", &id), ("label", "Twice")])
        .await?;
    assert_eq!(
        again.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a repeated id"
    );
    assert!(
        text(again)
            .await?
            .contains(&en(keys::WEB_ADMIN_NOTIFY_ERROR_CHAT_EXISTS)),
        "already listed"
    );
    let removed = fixture.post(REMOVE, &admin, &[("id", &id)]).await?;
    assert_eq!(removed.status(), StatusCode::OK, "removed");
    assert!(
        settings(&fixture)?.chats.as_slice().is_empty(),
        "no chat left"
    );
    for action in ["web.notify_chat_add", "web.notify_chat_remove"] {
        let entries = fixture.audited(action).await?;
        let params: Vec<_> = entries.iter().map(|entry| &entry.params_redacted).collect();
        assert_eq!(params, [&json!({"label": "Ops <team>"})], "{action}");
    }
    let joined = serde_json::to_string(&fixture.audited("web.notify_chat_add").await?)?;
    assert!(!joined.contains(&id), "no chat id in the audit log");
    Ok(())
}

/// Regression (todo 11): the test message goes through the running notifier once and the
/// page shows the result; a failure shows its class and is audited as failed.
#[tokio::test]
async fn the_test_message_goes_through_the_notifier_once() -> TestResult {
    for (answer, shown, outcome) in [
        (None, keys::WEB_ADMIN_NOTIFY_TEST_SENT, "success"),
        (
            Some(NotifyTestError::TokenRejected),
            keys::WEB_ADMIN_NOTIFY_TEST_TOKEN_REJECTED,
            "failed",
        ),
    ] {
        let stub = Stub::new(NotifyStatus::default(), answer);
        let fixture = Notify::build(Some(Arc::clone(&stub))).await?;
        let admin = fixture.login("admin").await?;
        let added = fixture
            .post(CHATS, &admin, &[("id", "@kcc_alerts"), ("label", "Alerts")])
            .await?;
        assert_eq!(added.status(), StatusCode::OK, "chat added");
        let sent = fixture
            .post(TEST, &admin, &[("chat", "@kcc_alerts")])
            .await?;
        assert_eq!(sent.status(), StatusCode::OK, "answered");
        assert!(text(sent).await?.contains(&en(shown)), "the result shown");
        assert_eq!(stub.sends(), ["@kcc_alerts"], "one send to the chosen chat");
        let outcomes: Vec<_> = fixture
            .audited("web.notify_test")
            .await?
            .into_iter()
            .map(|entry| entry.outcome)
            .collect();
        assert_eq!(outcomes, [outcome], "audited");
        let unknown = fixture
            .post(TEST, &admin, &[("chat", "@somebody_else")])
            .await?;
        assert_eq!(
            unknown.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown chat"
        );
        assert_eq!(stub.sends().len(), 1, "nothing sent to an unknown chat");
    }
    let without = Notify::build(None).await?;
    let admin = without.login("admin").await?;
    let added = without
        .post(CHATS, &admin, &[("id", "@kcc_alerts"), ("label", "Alerts")])
        .await?;
    assert_eq!(added.status(), StatusCode::OK, "chat added");
    let not_running = without
        .post(TEST, &admin, &[("chat", "@kcc_alerts")])
        .await?;
    assert!(
        text(not_running)
            .await?
            .contains(&en(keys::WEB_ADMIN_NOTIFY_TEST_NOT_RUNNING)),
        "no notifier in this process"
    );
    Ok(())
}

/// Regression (todo 11): every change of the page needs the session's CSRF token, and the
/// same change with it is accepted.
#[tokio::test]
async fn a_post_without_csrf_is_refused() -> TestResult {
    let stub = Stub::new(NotifyStatus::default(), None);
    let fixture = Notify::build(Some(Arc::clone(&stub))).await?;
    let admin = fixture.login("admin").await?;
    for (path, pairs) in [
        (PAGE, vec![("enabled", "on")]),
        ("/ui/admin/notifications/token", vec![("token", "1:x")]),
        (
            "/ui/admin/notifications/token/clear",
            vec![("confirm", "yes")],
        ),
        (CHATS, vec![("id", "@kcc_alerts"), ("label", "Alerts")]),
        (REMOVE, vec![("id", "@kcc_alerts")]),
        (TEST, vec![("chat", "@kcc_alerts")]),
    ] {
        let refused = fixture.post_without_csrf(path, &admin, &pairs).await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(
        fixture.store().read::<NotifySettings>()?.is_none(),
        "nothing stored"
    );
    assert!(
        stub.sends().is_empty() && stub.reloads() == 0,
        "the notifier untouched"
    );
    let accepted = fixture.post(PAGE, &admin, &[("enabled", "on")]).await?;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "the same change with the token"
    );
    Ok(())
}
