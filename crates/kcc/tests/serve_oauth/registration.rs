//! Todo 31 limits: registration rules and the login's resume id.

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;

    use kcc_app::{
        accounts::SystemClock,
        mcp_auth::clients::{ClientRegistration, ClientStore, ClientsDocument, MAX_CLIENTS},
    };
    use reqwest::{StatusCode, header};
    use serde_json::Value;

    use crate::{
        browser::{self, Browser},
        fixture::{Fixture, Options, PASSWORD, TestResult},
        flow::{self, REDIRECT, begin, client, location, register},
    };

    /// Todo 31: registration refuses a `javascript:` redirect URI and the 51st client
    /// (pre-registered ones count), and one address registers at most 10 clients an hour
    /// (refused registrations count).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registration_refuses_unsafe_redirects_and_limits() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let error = |body: &Value| body.get("error").and_then(Value::as_str).map(str::to_owned);
        let (status, body) = register(&fixture, &server, ("bad", &["javascript:alert(1)"])).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error(&body).as_deref(), Some("invalid_redirect_uri"));
        let store = ClientStore::new(fixture.state()?, Arc::new(SystemClock::default()));
        while store.document()?.clients().len() < MAX_CLIENTS.saturating_sub(1) {
            drop(store.register(&ClientRegistration::new(None, vec![REDIRECT.to_owned()]))?);
        }
        let (fiftieth, _) = register(&fixture, &server, ("x", &[REDIRECT])).await?;
        assert_eq!(fiftieth, StatusCode::CREATED);
        let (full, refusal) = register(&fixture, &server, ("x", &[REDIRECT])).await?;
        assert_eq!(full, StatusCode::BAD_REQUEST, "the 51st client");
        assert_eq!(error(&refusal).as_deref(), Some("invalid_client_metadata"));
        let count = fixture
            .state()?
            .read::<ClientsDocument>()?
            .ok_or("clients")?
            .clients()
            .len();
        assert_eq!(count, MAX_CLIENTS);
        for attempt in 4_u32..=10 {
            let (refused, _) = register(&fixture, &server, ("x", &[REDIRECT])).await?;
            assert_eq!(refused, StatusCode::BAD_REQUEST, "attempt {attempt}");
        }
        let (eleventh, _) = register(&fixture, &server, ("x", &[REDIRECT])).await?;
        assert_eq!(
            eleventh,
            StatusCode::TOO_MANY_REQUESTS,
            "the 11th registration"
        );
        Ok(())
    }

    /// Todo 31: the login's resume id is followed only when it names a live request; a URL
    /// or an unknown id signs in to the start page, and an unknown consent page is an
    /// error page.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consent_open_redirect_refused() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let live = begin(&fixture, &server, &first).await?;
        let hostile = [
            "https://evil.example/".to_owned(),
            "//evil.example".to_owned(),
            "../../admin".to_owned(),
            flow::unique("id").get(..43).unwrap_or_default().to_owned(),
        ];
        for id in hostile {
            let page = fixture
                .http()
                .get(format!("{}/ui/login", server.base()))
                .send()
                .await?;
            let cookie = browser::cookie_pair(&page)?;
            let csrf = browser::csrf(&page.text().await?)?;
            let signed = fixture
                .http()
                .post(format!("{}/ui/login", server.base()))
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, server.base())
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(flow::form(&[
                    ("username", "alice"),
                    ("password", PASSWORD),
                    ("consent", &id),
                ]))
                .send()
                .await?;
            assert_eq!(location(&signed).as_deref(), Some("/ui/"), "{id}");
            let unknown = fixture
                .http()
                .get(format!(
                    "{}/ui/oauth/consent?{}",
                    server.base(),
                    flow::form(&[("request", &id)])
                ))
                .send()
                .await?;
            assert_eq!(location(&unknown), None, "{id}");
        }
        let resumed = Browser::resume(&fixture, &server, ("alice", PASSWORD), &live.id).await;
        assert!(resumed.is_ok(), "a live id resumes: {:?}", resumed.err());
        Ok(())
    }
}
