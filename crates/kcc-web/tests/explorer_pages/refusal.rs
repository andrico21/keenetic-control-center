//! Refused console and explorer requests are answered in place.
//!
//! The 403 carries a fragment for the result region that names the missing permissions
//! in the account's language, and every signed-in page carries the refusal toast that
//! `app.js` shows for any other 403.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    form, html,
    support::{Fixture, TestResult, header_text, text},
};

/// Management requests the `raw-writer` role may not send.
///
/// The role holds `Read`, `Write` and `RawRci` (F3's `rawnd`); a management change also
/// needs `Destructive`. Each entry: the endpoint, the form, the region the answer belongs
/// in and the audit action.
fn management_requests() -> [(&'static str, String, &'static str, &'static str); 4] {
    [
        (
            "/ui/r/home/console/cli/send",
            form(&[("line", "ip ssh port 2228")]),
            "#cli-result",
            "web.console_cli",
        ),
        (
            "/ui/r/home/console/cli/send",
            form(&[("line", "no ip name-server 192.0.2.53")]),
            "#cli-result",
            "web.console_cli",
        ),
        (
            "/ui/r/home/console/rci/send",
            form(&[
                ("method", "POST"),
                ("path", ""),
                ("body", r#"[{"service":{"http":{"no":true}}}]"#),
            ]),
            "#rci-result",
            "web.console_rci",
        ),
        (
            "/ui/r/home/explorer/execute",
            form(&[("path", "ip http port"), ("a.port", "8080")]),
            "#explorer-result",
            "web.explorer_execute",
        ),
    ]
}

/// The refusal's two sentences in `locale` for one missing permission labelled `label`,
/// each with the marker of its message, escaped as the page shows them.
fn refusal(locale: Locale, label: MessageKey) -> [String; 2] {
    let mut args = FluentArgs::new();
    args.set("count", 1_u32);
    args.set("permissions", tr(locale, label, None));
    [
        (
            keys::WEB_REFUSAL_TITLE,
            tr(locale, keys::WEB_REFUSAL_TITLE, None),
        ),
        (
            keys::WEB_REFUSAL_MISSING,
            tr(locale, keys::WEB_REFUSAL_MISSING, Some(&args)),
        ),
    ]
    .map(|(key, sentence)| format!("data-message-key=\"{}\">{}<", key.id(), html(&sentence)))
}

/// A raw writer's refused management request names `Destructive` in its result region.
///
/// The line, body or explorer form answers 403; nothing reaches the router and each
/// refusal stays audited as `forbidden`.
#[tokio::test]
async fn refused_requests_name_the_missing_permission_in_place() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("raw-writer").await?;
    drop(fixture.get("/ui/r/home/console/cli", &browser).await?);
    let expected = refusal(Locale::En, keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE);
    for (endpoint, request, region, _) in management_requests() {
        let before = fixture.handle().request_count();
        let response = fixture.post(endpoint, &browser, &request).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{request}");
        assert_eq!(
            header_text(&response, "hx-retarget").as_deref(),
            Some(region),
            "the result region: {request}"
        );
        let body = text(response).await?;
        for sentence in &expected {
            assert!(body.contains(sentence), "{sentence} for {request}: {body}");
        }
        assert!(!body.contains("<html"), "a fragment, not a page: {body}");
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "nothing sent: {request}"
        );
    }
    let audited: Vec<_> = fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.outcome == "forbidden")
        .map(|entry| entry.action)
        .collect();
    let actions = management_requests().map(|(_, _, _, action)| action);
    assert_eq!(audited, actions, "every refusal audited");
    Ok(())
}

/// A role without `RawRci` that posts a change to the explorer is told it lacks
/// `Raw RCI and CLI`.
#[tokio::test]
async fn a_role_without_raw_access_is_told_which_permission_it_lacks() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            "/ui/r/home/explorer/execute",
            &operator,
            &form(&[
                ("path", "ip hotspot host"),
                ("a.mac", "02:00:00:00:00:99"),
                ("a.permit", "true"),
            ]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "refused");
    let body = text(response).await?;
    for sentence in refusal(Locale::En, keys::WEB_ADMIN_PERMISSION_RAW_RCI) {
        assert!(body.contains(&sentence), "{sentence}: {body}");
    }
    Ok(())
}

/// The refusal is in the account's language in every locale: its own sentences and
/// permission name, never English in their place and no unfilled variable.
#[tokio::test]
async fn refusals_speak_the_account_language() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("raw-writer").await?;
    let english = refusal(Locale::En, keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE);
    for locale in Locale::ALL {
        let tag = locale.tag();
        let chosen = fixture
            .post("/ui/account/locale", &browser, &format!("locale={tag}"))
            .await?;
        assert_eq!(chosen.status(), StatusCode::OK, "{tag} saved");
        let response = fixture
            .post(
                "/ui/r/home/console/cli/send",
                &browser,
                &form(&[("line", "ip ssh port 2228")]),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{tag}");
        let body = text(response).await?;
        let expected = refusal(locale, keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE);
        for sentence in &expected {
            assert!(body.contains(sentence), "{tag}: {sentence}: {body}");
        }
        assert!(!body.contains("{$"), "{tag}: every variable filled: {body}");
        if locale != Locale::En {
            assert_ne!(expected, english, "{tag} has its own sentences");
        }
    }
    Ok(())
}

/// Every signed-in page carries the refusal toast in the account's language: `app.js`
/// shows it for a 403 that names no region.
#[tokio::test]
async fn pages_carry_the_refusal_toast_in_the_account_language() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("raw-writer").await?;
    for locale in [Locale::En, Locale::Ru, Locale::De, Locale::Kk] {
        let tag = locale.tag();
        let chosen = fixture
            .post("/ui/account/locale", &browser, &format!("locale={tag}"))
            .await?;
        assert_eq!(chosen.status(), StatusCode::OK, "{tag} saved");
        let page = text(fixture.get("/ui/r/home/console/cli", &browser).await?).await?;
        let toast = page
            .split_once("<template id=\"refused-toast\">")
            .and_then(|(_, tail)| tail.split_once("</template>"))
            .map(|(inside, _)| inside)
            .ok_or("no refusal toast template")?;
        let message = html(&tr(locale, keys::WEB_REFUSAL_TOAST, None));
        assert!(
            toast.contains("class=\"toast\" data-tone=\"error\"") && toast.contains(&message),
            "{tag}: {toast}"
        );
    }
    Ok(())
}
