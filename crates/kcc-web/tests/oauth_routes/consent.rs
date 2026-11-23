//! Todo 31: the consent page and its decisions.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use axum::{http::StatusCode, response::Response};
    use kcc_app::accounts::{AccountChange, UsersDocument};
    use url::Url;

    use crate::{
        harness::{Harness, ISSUER, REDIRECT, RESOURCE, pkce},
        support::{
            outcome::TestResult,
            page::{header_text, text},
        },
    };

    /// The query pairs of an `HX-Redirect`.
    fn hx_query(response: &Response) -> TestResult<Vec<(String, String)>> {
        let target = header_text(response, "hx-redirect").ok_or("no HX-Redirect")?;
        assert!(target.starts_with(REDIRECT), "{target}");
        Ok(Url::parse(&target)?.query_pairs().into_owned().collect())
    }

    /// The value of `name` in `pairs`.
    fn value<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Todo 31: the consent page shows who asks for whom.
    ///
    /// Without a session it is the login page carrying the request id; the sign-in resumes
    /// there. The page shows the client's name escaped and marked unverified, the redirect
    /// host, the account and its role.
    #[tokio::test]
    async fn the_consent_page_shows_who_asks_for_whom() -> TestResult {
        let harness = Harness::new("<script>alert(1)</script>")?;
        let (_, challenge) = pkce("page");
        let id = harness.begin(&challenge, "s").await?;
        let login = harness
            .get(&format!("/ui/oauth/consent?request={id}"), None)
            .await?;
        assert_eq!(login.status(), StatusCode::OK);
        let html = text(login).await?;
        assert!(
            html.contains(&format!("name=\"consent\" value=\"{id}\"")),
            "{html}"
        );
        let (browser, location) = harness.sign_in("vera", &id).await?;
        assert_eq!(location, Some(format!("/ui/oauth/consent?request={id}")));
        let page = text(
            harness
                .get(
                    &format!("/ui/oauth/consent?request={id}"),
                    Some(&browser.cookie),
                )
                .await?,
        )
        .await?;
        assert!(
            !page.contains("<script>alert(1)</script>"),
            "the name is escaped"
        );
        assert!(
            page.contains("id=\"oauth-client-name\">&#60;script&#62;alert(1)&#60;/script&#62;<"),
            "{page}"
        );
        assert!(page.contains("id=\"oauth-client-unverified\""));
        assert!(page.contains("id=\"oauth-redirect-host\">127.0.0.1<"));
        assert!(page.contains("id=\"oauth-account\">vera<"));
        assert!(page.contains("id=\"oauth-role\">viewer<"));
        assert!(page.contains(&format!("id=\"oauth-resource\">{RESOURCE}<")));
        Ok(())
    }

    /// Todo 31: the sign-in follows only a live request id; a URL, a path or an unknown id
    /// lands on the start page.
    #[tokio::test]
    async fn the_login_resumes_only_at_a_live_request() -> TestResult {
        let harness = Harness::new("client")?;
        let (_, challenge) = pkce("resume");
        let live = harness.begin(&challenge, "s").await?;
        for hostile in [
            "https://evil.example/",
            "//evil.example",
            "/ui/admin",
            "unknown",
        ] {
            let (_, location) = harness.sign_in("alice", hostile).await?;
            assert_eq!(location.as_deref(), Some("/ui/"), "{hostile}");
        }
        let (_, location) = harness.sign_in("alice", &live).await?;
        assert_eq!(location, Some(format!("/ui/oauth/consent?request={live}")));
        Ok(())
    }

    /// Todo 31: approve and deny need the session's CSRF token; without it the request
    /// stays pending. Approve answers the code with the state and `iss`, deny
    /// `access_denied` with both; a request is used once.
    #[tokio::test]
    async fn decisions_need_the_csrf_token_and_answer_the_client() -> TestResult {
        let harness = Harness::new("client")?;
        let (_, challenge) = pkce("decide");
        let id = harness.begin(&challenge, "kept-state").await?;
        let (browser, _) = harness.sign_in("alice", &id).await?;
        for decision in ["approve", "deny"] {
            let forged = harness
                .post(
                    &format!("/ui/oauth/consent/{decision}"),
                    (&browser, false),
                    &[("request", &id)],
                )
                .await?;
            assert_eq!(forged.status(), StatusCode::FORBIDDEN, "{decision}");
        }
        let approved = harness
            .post(
                "/ui/oauth/consent/approve",
                (&browser, true),
                &[("request", &id)],
            )
            .await?;
        let query = hx_query(&approved)?;
        assert!(value(&query, "code").is_some_and(|code| code.len() == 43));
        assert_eq!(value(&query, "state"), Some("kept-state"));
        assert_eq!(value(&query, "iss"), Some(ISSUER));
        let again = harness
            .post(
                "/ui/oauth/consent/approve",
                (&browser, true),
                &[("request", &id)],
            )
            .await?;
        assert_eq!(header_text(&again, "hx-redirect"), None, "used once");
        let denied_id = harness.begin(&challenge, "other").await?;
        let denied = harness
            .post(
                "/ui/oauth/consent/deny",
                (&browser, true),
                &[("request", &denied_id)],
            )
            .await?;
        let refusal = hx_query(&denied)?;
        assert_eq!(value(&refusal, "error"), Some("access_denied"));
        assert_eq!(value(&refusal, "state"), Some("other"));
        assert_eq!(value(&refusal, "iss"), Some(ISSUER));
        assert_eq!(value(&refusal, "code"), None);
        Ok(())
    }

    /// Todo 31: an account that was disabled, or must change its password, after signing
    /// in gets no consent page, no code from an approval, and no token for a code
    /// approved before the change.
    #[tokio::test]
    async fn an_account_that_cannot_sign_in_gets_nothing() -> TestResult {
        for change in ["disabled", "must_change_password"] {
            let harness = Harness::new("client")?;
            let (verifier, challenge) = pkce("standing");
            let earlier = harness.begin(&challenge, "s").await?;
            let code = harness.approved_code("vera", &earlier).await?;
            let id = harness.begin(&challenge, "s").await?;
            let (browser, _) = harness.sign_in("vera", &id).await?;
            if change == "disabled" {
                drop(
                    harness
                        .accounts()
                        .administer("vera", &AccountChange::Disabled(true))?,
                );
            } else {
                harness.state().update(|document: &mut UsersDocument| {
                    for account in &mut document.users {
                        account.must_change_password |= account.username == "vera";
                    }
                })?;
            }
            let page = harness
                .get(
                    &format!("/ui/oauth/consent?request={id}"),
                    Some(&browser.cookie),
                )
                .await?;
            assert_eq!(
                page.status(),
                StatusCode::FORBIDDEN,
                "{change}: consent page"
            );
            let approved = harness
                .post(
                    "/ui/oauth/consent/approve",
                    (&browser, true),
                    &[("request", &id)],
                )
                .await?;
            assert_eq!(
                header_text(&approved, "hx-redirect"),
                None,
                "{change}: approve"
            );
            assert!(
                text(approved).await?.contains("web-oauth-error-account"),
                "{change}"
            );
            let token = harness
                .protocol(
                    "/oauth/token",
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", &code),
                        ("redirect_uri", REDIRECT),
                        ("client_id", &harness.client),
                        ("code_verifier", &verifier),
                        ("resource", RESOURCE),
                    ],
                )
                .await?;
            assert_eq!(
                token.status(),
                StatusCode::BAD_REQUEST,
                "{change}: token(code)"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod password {
    use axum::http::StatusCode;
    use secrecy::SecretString;

    use crate::{
        harness::{Harness, REDIRECT, RESOURCE, pkce},
        support::{base::PASSWORD, outcome::TestResult},
    };

    /// Todo 31: a code approved before the account's password changed issues no token,
    /// though the account may still sign in.
    #[tokio::test]
    async fn a_code_approved_before_a_password_change_issues_nothing() -> TestResult {
        let harness = Harness::new("client")?;
        let (verifier, challenge) = pkce("password");
        let id = harness.begin(&challenge, "s").await?;
        let code = harness.approved_code("vera", &id).await?;
        drop(harness.accounts().change_password(
            "vera",
            &SecretString::from(PASSWORD),
            &SecretString::from("another horse battery staple"),
        )?);
        let token = harness
            .protocol(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", REDIRECT),
                    ("client_id", &harness.client),
                    ("code_verifier", &verifier),
                    ("resource", RESOURCE),
                ],
            )
            .await?;
        assert_eq!(token.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
