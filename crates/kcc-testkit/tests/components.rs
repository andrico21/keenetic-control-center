//! Staged component and reboot-window integration tests.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{error::Error, net::SocketAddr, time::Duration};

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use kcc_rci::{RouterUrl, auth::Credentials, capabilities::RouterInfo};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::Profile,
        ndw2,
        outbound::connect_manager,
        time::{Clock, MockClock},
    };
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    /// Builds default credentials.
    fn credentials() -> Credentials {
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        )
    }

    /// Opens an independently observable authenticated cookie.
    async fn login(app: &Router, realm: &str) -> TestResult<String> {
        let challenge = app
            .clone()
            .oneshot(Request::get("/auth").body(Body::empty())?)
            .await?;
        let cookie = challenge
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .ok_or("missing cookie")?
            .to_owned();
        let token = challenge
            .headers()
            .get("x-ndm-challenge")
            .and_then(|value| value.to_str().ok())
            .ok_or("missing challenge")?;
        let password = ndw2::response(DEFAULT_LOGIN, realm, DEFAULT_PASSWORD, token);
        let response = app
            .clone()
            .oneshot(
                Request::post("/auth")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(
                        json!({"login":DEFAULT_LOGIN,"password":password}).to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(cookie)
    }

    /// Reads one response body as JSON.
    async fn json_body(response: Response) -> TestResult<Value> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), usize::MAX).await?,
        )?)
    }

    /// Commit is unreachable until clock advance, then applies components and invalidates cookies.
    #[tokio::test]
    async fn commit_applies_after_clock_window_and_redetects_router() -> TestResult {
        let clock = Arc::new(MockClock::new());
        let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
        let fake = FakeRouter::builder(Profile::default())
            .clock(injected)
            .build()?;
        let app = fake.router();
        let old_cookie = login(&app, fake.realm()).await?;
        let (address, handle) = fake
            .clone()
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        let router = format!("http://{address}").parse::<RouterUrl>()?;
        let policy = kcc_rci::OutboundPolicy::default().with_loopback(true);
        let manager = connect_manager(router.clone(), credentials(), &policy).await?;
        let before = RouterInfo::detect(&manager, &router).await?;

        drop(
            manager
                .post("/rci/", &json!({"parse":"components install ftp"}))
                .await?,
        );
        drop(
            manager
                .post("/rci/", &json!({"parse":"components remove ipsec"}))
                .await?,
        );
        let pending = manager
            .get("/rci/show/components/pending")
            .await?
            .json::<Value>()
            .await?;
        assert_eq!(pending.pointer("/install/0"), Some(&json!("ftp")));
        assert_eq!(pending.pointer("/remove/0"), Some(&json!("ipsec")));
        let committed = manager
            .post("/rci/", &json!({"parse":"components commit"}))
            .await?;
        assert!(committed.status().is_success());

        assert_eq!(
            manager.get("/rci/show/version").await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        clock.advance(Duration::from_secs(5));
        let old_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/rci/show/version")
                    .header(header::COOKIE, old_cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(old_response.status(), StatusCode::UNAUTHORIZED);

        let refreshed = connect_manager(router.clone(), credentials(), &policy).await?;
        let after = RouterInfo::detect(&refreshed, &router).await?;
        assert_eq!(after.version.title.as_deref(), Some("5.1.4"));
        assert_eq!(after.version.release.as_deref(), Some("5.01.C.4.0-0"));
        assert!(after.components.contains("ftp"));
        assert!(!after.components.contains("ipsec"));
        assert_ne!(after.components, before.components);
        let listed = app
            .oneshot(
                Request::get("/rci/show/components/list")
                    .header(header::COOKIE, login(&fake.router(), fake.realm()).await?)
                    .body(Body::empty())?,
            )
            .await?;
        let list = json_body(listed).await?;
        assert!(list.as_array().is_some_and(|rows| rows.iter().any(|row| {
            row.get("name") == Some(&json!("ftp")) && row.get("installed") == Some(&json!(true))
        })));
        handle.shutdown().await?;
        Ok(())
    }
}
