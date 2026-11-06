//! The domain page kit over HTTP, across the pages built on it: the router of a route is
//! resolved and the operation's permissions checked before anything runs, refusals are
//! audited, and a secret typed into a page reaches neither a page nor the audit log.

#[expect(
    dead_code,
    reason = "the shared explorer fixture; this suite needs only part of it"
)]
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
    use url::form_urlencoded::byte_serialize;

    use crate::support::{Fixture, TestResult, text};

    /// `pairs` form-encoded.
    fn form(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    byte_serialize(name.as_bytes()).collect::<String>(),
                    byte_serialize(value.as_bytes()).collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    #[tokio::test]
    async fn routers_and_permissions_are_checked_before_anything_runs() -> TestResult {
        let fixture = Fixture::new().await?;
        let viewer = fixture.login("viewer").await?;
        drop(fixture.get("/ui/r/home/system/general", &viewer).await?);
        let before = fixture.handle().request_count();
        let malformed = fixture
            .get("/ui/r/no%20such/system/general", &viewer)
            .await?;
        assert_eq!(malformed.status(), StatusCode::NOT_FOUND, "malformed id");
        let operator = fixture.login("operator").await?;
        let unknown = fixture
            .post(
                "/ui/r/cottage/system/general/hostname",
                &operator,
                "value=office-1",
            )
            .await?;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown router");
        let refused = fixture
            .post(
                "/ui/r/home/system/general/hostname",
                &viewer,
                "value=office-1",
            )
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "viewer writes nothing"
        );
        let guarded = fixture
            .post(
                "/ui/r/home/system/general/reboot",
                &operator,
                "confirm=yes&confirm_name=home",
            )
            .await?;
        assert_eq!(
            guarded.status(),
            StatusCode::FORBIDDEN,
            "operator restarts nothing"
        );
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "the router heard none of it"
        );
        let audit = fixture.audit()?;
        for (action, account) in [
            ("web.system_hostname", "viewer"),
            ("web.system_reboot", "operator"),
        ] {
            assert!(
                audit.iter().any(|entry| entry.action == action
                    && entry.outcome == "forbidden"
                    && entry.actor.id == account
                    && entry.router.as_deref() == Some("home")),
                "{action} refusal audited"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn secrets_reach_neither_a_page_nor_the_audit_log() -> TestResult {
        let fixture = Fixture::new().await?;
        let admin = fixture.login("admin").await?;
        let secret = "kit-secret-7d1f";
        let fields = [
            ("path", "user password plain"),
            ("a.password", secret),
            ("confirm", "yes"),
        ];
        let preview = text(
            fixture
                .post("/ui/r/home/explorer/preview", &admin, &form(&fields))
                .await?,
        )
        .await?;
        assert!(preview.contains("********"), "masked preview: {preview}");
        let executed = fixture
            .post("/ui/r/home/explorer/execute", &admin, &form(&fields))
            .await?;
        assert_eq!(executed.status(), StatusCode::OK, "answered");
        let answer = text(executed).await?;
        let refused = fixture
            .post(
                "/ui/routers/new",
                &admin,
                &form(&[
                    ("id", "not a slug"),
                    ("url", "http://192.0.2.1"),
                    ("login", "admin"),
                    ("password", secret),
                    ("tls", "verify"),
                ]),
            )
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "the router form shows its errors"
        );
        let form_page = text(refused).await?;
        assert!(
            form_page.contains("name=\"password\" type=\"password\" value=\"\""),
            "the write-only field stays empty"
        );
        for (page, html) in [
            ("preview", &preview),
            ("answer", &answer),
            ("form", &form_page),
        ] {
            assert!(!html.contains(secret), "{page} shows the secret: {html}");
        }
        let audit = fixture.audit()?;
        assert!(
            audit
                .iter()
                .any(|entry| entry.action == "web.explorer_execute"),
            "the execution is audited"
        );
        assert!(
            !serde_json::to_string(&audit)?.contains(secret),
            "the audit log holds field names only"
        );
        Ok(())
    }
}
