//! The system general page, the page kit's reference page, against the fake router: what
//! each role sees, a change applied and read back with the unsaved badge, a silent no-op
//! caught by the read-back, a value refused before anything is sent, a router refusal,
//! and the restart that needs the router name.

#[path = "explorer_pages/support.rs"]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use axum::http::StatusCode;
    use fluent_bundle::FluentArgs;
    use kcc_i18n::{
        bundle::{MessageKey, tr},
        keys,
        locale::Locale,
    };
    use kcc_rci::{RciBody, RciPath};
    use kcc_testkit::FaultInjection;
    use url::form_urlencoded::byte_serialize;

    use crate::support::{Fixture, ROUTER, TestResult, header_text, text};

    /// The page under test.
    const PAGE: &str = "/ui/r/home/system/general";

    /// `text` as askama escapes it.
    fn html(text: &str) -> String {
        text.replace('&', "&#38;")
            .replace('<', "&#60;")
            .replace('>', "&#62;")
            .replace('"', "&#34;")
            .replace('\'', "&#39;")
    }

    /// A message in `locale`, escaped for HTML.
    fn said(locale: Locale, key: MessageKey) -> String {
        html(&tr(locale, key, None))
    }

    /// `value` as the one field of a dialog form.
    fn value(value: &str) -> String {
        format!(
            "value={}",
            byte_serialize(value.as_bytes()).collect::<String>()
        )
    }

    /// The configured `system` settings on the fake router.
    async fn configured(fixture: &Fixture) -> TestResult<serde_json::Value> {
        let client = fixture.registry().client(ROUTER).await?;
        match client
            .get(&RciPath::from_segments(["system"])?, &())
            .await?
        {
            RciBody::Json(response) => Ok(response.value),
            RciBody::Text(_) | _ => Err("system settings are not JSON".into()),
        }
    }

    #[tokio::test]
    async fn each_role_sees_the_settings_and_only_its_controls() -> TestResult {
        let fixture = Fixture::new().await?;
        let hostname_dialog = "hx-get=\"/ui/r/home/system/general/hostname\"";
        let restart = "hx-post=\"/ui/r/home/system/general/reboot\"";
        for (account, edits, restarts) in [
            ("viewer", false, false),
            ("operator", true, false),
            ("admin", true, true),
        ] {
            let browser = fixture.login(account).await?;
            let response = fixture.get(PAGE, &browser).await?;
            assert_eq!(response.status(), StatusCode::OK, "{account}");
            let page = text(response).await?;
            for shown in [
                said(Locale::En, keys::WEB_SYSTEM_GENERAL_TITLE),
                "host-1".to_owned(),
                "fixture router".to_owned(),
                "fixture.invalid".to_owned(),
                "UTC".to_owned(),
                "2026-01-01 00:00:00".to_owned(),
                said(Locale::En, keys::WEB_KIT_NOT_REPORTED),
                "id=\"page-outcome\"".to_owned(),
                "<option value=\"home\" selected>".to_owned(),
            ] {
                assert!(page.contains(&shown), "{account} misses {shown}");
            }
            assert_eq!(page.contains(hostname_dialog), edits, "{account} edit");
            assert_eq!(page.contains(restart), restarts, "{account} restart");
        }
        let viewer = fixture.login("viewer").await?;
        let refused = fixture
            .post(&format!("{PAGE}/hostname"), &viewer, &value("office-1"))
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "the route checks too"
        );
        let dialog = fixture.get(&format!("{PAGE}/hostname"), &viewer).await?;
        assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
        let missing = fixture.get("/ui/r/cottage/system/general", &viewer).await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "unknown router");
        let ukrainian = fixture.login("ukrainian").await?;
        let localized = text(fixture.get(PAGE, &ukrainian).await?).await?;
        assert!(
            localized.contains(&said(Locale::Uk, keys::WEB_SYSTEM_GENERAL_TITLE)),
            "the account's language"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_change_is_read_back_and_shows_the_unsaved_badge() -> TestResult {
        let fixture = Fixture::new().await?;
        let operator = fixture.login("operator").await?;
        let dialog = fixture
            .get(&format!("{PAGE}/description"), &operator)
            .await?;
        assert_eq!(dialog.status(), StatusCode::OK, "dialog");
        assert!(
            text(dialog).await?.contains("value=\"fixture router\""),
            "the dialog starts from the current value"
        );
        let wanted = "Office, 2nd floor";
        let response = fixture
            .post(&format!("{PAGE}/description"), &operator, &value(wanted))
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "applied");
        assert_eq!(
            header_text(&response, "hx-trigger").as_deref(),
            Some("kcc:dialog-close"),
            "the dialog closes"
        );
        let body = text(response).await?;
        for expected in [
            said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
            "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
            "hx-swap-oob=\"beforeend:#toasts\"".to_owned(),
            "id=\"general-settings\" hx-swap-oob=\"true\"".to_owned(),
            wanted.to_owned(),
        ] {
            assert!(body.contains(&expected), "missing {expected} in {body}");
        }
        assert_eq!(
            configured(&fixture).await?.get("description"),
            Some(&serde_json::Value::String(wanted.to_owned())),
            "the router has it"
        );
        assert_eq!(fixture.backups()?, 1, "one pre-change backup");
        let audit = fixture.audit()?;
        let web = audit
            .iter()
            .find(|entry| entry.action == "web.system_description")
            .ok_or("no web audit")?;
        assert_eq!(web.outcome, "success", "outcome");
        assert_eq!(web.router.as_deref(), Some(ROUTER), "router");
        assert!(
            audit.iter().any(|entry| entry.action == "router.change"
                && entry.target.as_deref() == Some("system description")),
            "the change workflow's own entry"
        );
        assert!(
            audit
                .iter()
                .all(|entry| !entry.params_redacted.to_string().contains(wanted)),
            "field names only"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_silent_no_op_names_the_field_read_back() -> TestResult {
        let fixture =
            Fixture::with_faults(FaultInjection::default().silent_noop_path("system")).await?;
        let operator = fixture.login("operator").await?;
        let response = fixture
            .post(&format!("{PAGE}/hostname"), &operator, &value("office-1"))
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "answered");
        let body = text(response).await?;
        let mut args = FluentArgs::new();
        args.set("field", "/name");
        let expected = html(&tr(
            Locale::En,
            keys::WEB_KIT_VERIFICATION_FAILED,
            Some(&args),
        ));
        assert!(body.contains(&expected), "names the field: {body}");
        assert!(!body.contains("unsaved-badge"), "no badge for a failure");
        let audit = fixture.audit()?;
        assert!(
            audit
                .iter()
                .any(|entry| entry.action == "web.system_hostname"
                    && entry.outcome == "verification_failed"),
            "audited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_invalid_value_is_refused_before_anything_is_sent() -> TestResult {
        let fixture = Fixture::new().await?;
        let operator = fixture.login("operator").await?;
        drop(fixture.get(PAGE, &operator).await?);
        let before = fixture.handle().request_count();
        let response = fixture
            .post(&format!("{PAGE}/hostname"), &operator, &value("bad host!"))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "field error"
        );
        assert_eq!(
            header_text(&response, "hx-retarget").as_deref(),
            Some("#dialog-content"),
            "back into the dialog"
        );
        let body = text(response).await?;
        assert!(
            body.contains(&said(Locale::En, keys::WEB_SYSTEM_HOSTNAME_ERROR)),
            "the rule: {body}"
        );
        assert!(body.contains("value=\"bad host!\""), "the value as typed");
        assert_eq!(fixture.handle().request_count(), before, "nothing sent");
        assert!(
            fixture
                .audit()?
                .iter()
                .any(|entry| entry.action == "web.system_hostname"
                    && entry.outcome == "validation_failed"),
            "audited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restart_is_destructive_and_needs_the_router_name() -> TestResult {
        let fixture = Fixture::new().await?;
        let reboot = format!("{PAGE}/reboot");
        let operator = fixture.login("operator").await?;
        let denied = fixture.post(&reboot, &operator, "").await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
        let admin = fixture.login("admin").await?;
        let asked = fixture.post(&reboot, &admin, "").await?;
        assert_eq!(
            header_text(&asked, "hx-retarget").as_deref(),
            Some("#dialog-content"),
            "dialog"
        );
        let prompt = text(asked).await?;
        assert!(
            prompt.contains(&said(Locale::En, keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
            "asks: {prompt}"
        );
        assert!(prompt.contains("name=\"confirm_name\""), "the name field");
        let mistyped = text(
            fixture
                .post(&reboot, &admin, "confirm=yes&confirm_name=Home")
                .await?,
        )
        .await?;
        let mut args = FluentArgs::new();
        args.set("router", ROUTER);
        let mismatch = html(&tr(
            Locale::En,
            keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
            Some(&args),
        ));
        assert!(mistyped.contains(&mismatch), "mismatch: {mistyped}");
        assert!(
            !fixture
                .audit()?
                .iter()
                .any(|entry| entry.action == "router.change_cli_terminal"),
            "nothing ran yet"
        );
        let done = fixture
            .post(&reboot, &admin, "confirm=yes&confirm_name=home")
            .await?;
        assert_eq!(done.status(), StatusCode::OK, "restarted");
        let body = text(done).await?;
        assert!(
            body.contains(&said(Locale::En, keys::WEB_KIT_DONE_TERMINAL)),
            "the router is on it: {body}"
        );
        assert!(!body.contains("unsaved-badge"), "state unknown, no badge");
        let audit = fixture.audit()?;
        assert!(
            audit
                .iter()
                .any(|entry| entry.action == "router.change_cli_terminal"
                    && entry.target.as_deref() == Some("system reboot")),
            "terminal change"
        );
        assert!(
            audit
                .iter()
                .any(|entry| entry.action == "web.system_reboot" && entry.outcome == "success"),
            "audited"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
        let fixture =
            Fixture::with_faults(FaultInjection::default().fail_parse_matching("system reboot", 1))
                .await?;
        let admin = fixture.login("admin").await?;
        let response = fixture
            .post(
                &format!("{PAGE}/reboot"),
                &admin,
                "confirm=yes&confirm_name=home",
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "answered");
        let body = text(response).await?;
        assert!(
            body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
            "localized: {body}"
        );
        assert!(
            body.contains(&said(Locale::En, keys::WEB_EXPLORER_ROUTER_SAID)),
            "router said block"
        );
        let said_block = body
            .split_once("<ul class=\"router-said__list\">")
            .and_then(|(_, tail)| tail.split_once("</ul>"))
            .map(|(list, _)| list.to_owned())
            .ok_or("no router-said list")?;
        assert!(said_block.contains("<li>"), "the router's message");
        assert!(
            !said_block.contains("system reboot"),
            "no request body: {said_block}"
        );
        assert!(
            fixture
                .audit()?
                .iter()
                .any(|entry| entry.action == "web.system_reboot" && entry.outcome == "rci_error"),
            "audited"
        );
        Ok(())
    }
}
