//! Fail-safe state-machine integration tests.

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
    use core::{error::Error, time::Duration};

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
    };
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::Profile,
        ndw2,
        time::{Clock, MockClock},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Body,
    ) -> TestResult<(StatusCode, String)> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(value) = cookie {
            builder = builder.header(header::COOKIE, value);
        }
        let response = app.clone().oneshot(builder.body(body)?).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, String::from_utf8(bytes.to_vec())?))
    }

    async fn login(app: &Router, realm: &str) -> TestResult<String> {
        let response = app
            .clone()
            .oneshot(Request::get("/auth").body(Body::empty())?)
            .await?;
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        let challenge = response
            .headers()
            .get("x-ndm-challenge")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let password = ndw2::response(DEFAULT_LOGIN, realm, DEFAULT_PASSWORD, challenge);
        let body = json!({"login": DEFAULT_LOGIN, "password": password}).to_string();
        let (status, _) = send(app, Method::POST, "/auth", Some(&cookie), Body::from(body)).await?;
        assert_eq!(status, StatusCode::OK);
        Ok(cookie)
    }

    async fn parse(app: &Router, cookie: &str, command: &str) -> TestResult<Value> {
        let (_, body) = send(
            app,
            Method::POST,
            "/rci/",
            Some(cookie),
            Body::from(json!({"parse":command}).to_string()),
        )
        .await?;
        Ok(serde_json::from_str(&body)?)
    }

    #[tokio::test]
    async fn expiry_restores_startup_and_drops_sessions() -> TestResult {
        let clock = Arc::new(MockClock::new());
        let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
        let fake = FakeRouter::builder(Profile::default())
            .clock(injected)
            .build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        drop(
            parse(
                &app,
                &cookie,
                "system configuration fail-safe timer reboot 60",
            )
            .await?,
        );
        drop(
            parse(
                &app,
                &cookie,
                "interface Bridge0 description \"Temporary LAN\"",
            )
            .await?,
        );
        let (_, state_body) = send(
            &app,
            Method::GET,
            "/rci/show/last-change",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        let state: Value = serde_json::from_str(&state_body)?;
        assert_eq!(state.pointer("/fail-safe/active"), Some(&json!(true)));
        assert_eq!(state.get("unsaved"), Some(&json!(true)));

        clock.advance(Duration::from_secs(61));
        let (old_status, _) = send(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(old_status, StatusCode::UNAUTHORIZED);
        let new_cookie = login(&app, fake.realm()).await?;
        let (_, running) = send(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&new_cookie),
            Body::empty(),
        )
        .await?;
        assert!(!running.contains("Temporary LAN"));
        Ok(())
    }

    #[tokio::test]
    async fn keep_alive_restarts_timer_and_commit_saves() -> TestResult {
        let clock = Arc::new(MockClock::new());
        let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
        let fake = FakeRouter::builder(Profile::default())
            .clock(injected)
            .build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        drop(
            parse(
                &app,
                &cookie,
                "system configuration fail-safe timer reboot 60",
            )
            .await?,
        );
        drop(
            parse(
                &app,
                &cookie,
                "interface Bridge0 description \"Committed LAN\"",
            )
            .await?,
        );
        clock.advance(Duration::from_secs(50));
        drop(parse(&app, &cookie, "system configuration fail-safe keep-alive").await?);
        clock.advance(Duration::from_secs(50));
        let (status, _) = send(
            &app,
            Method::GET,
            "/rci/show/last-change",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        drop(parse(&app, &cookie, "system configuration fail-safe commit").await?);
        let (_, startup) = send(
            &app,
            Method::GET,
            "/ci/startup-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert!(startup.contains("Committed LAN"));
        Ok(())
    }
}
