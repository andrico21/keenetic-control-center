//! CLI parse and configuration-file integration tests.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
    };
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile, ndw2};
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    async fn request(
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
        let (status, _) =
            request(app, Method::POST, "/auth", Some(&cookie), Body::from(body)).await?;
        assert_eq!(status, StatusCode::OK);
        Ok(cookie)
    }

    #[tokio::test]
    async fn parse_changes_running_only_until_save() -> TestResult {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        let (_, startup_before) = request(
            &app,
            Method::GET,
            "/ci/startup-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        let command = json!({"parse": "interface Bridge0 description \"Home LAN\""});
        let (_, answer) = request(
            &app,
            Method::POST,
            "/rci/",
            Some(&cookie),
            Body::from(command.to_string()),
        )
        .await?;
        let parsed_answer: Value = serde_json::from_str(&answer)?;
        assert_eq!(
            parsed_answer.pointer("/status/0/status"),
            Some(&json!("message"))
        );
        let (_, running) = request(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        let (_, startup) = request(
            &app,
            Method::GET,
            "/ci/startup-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert!(running.contains("description \"Home LAN\""));
        assert_eq!(startup, startup_before);
        assert!(!startup.contains("description \"Home LAN\""));

        let save = json!({"parse": "system configuration save"});
        drop(
            request(
                &app,
                Method::POST,
                "/rci/",
                Some(&cookie),
                Body::from(save.to_string()),
            )
            .await?,
        );
        let (_, saved) = request(
            &app,
            Method::GET,
            "/ci/startup-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert!(saved.contains("description \"Home LAN\""));
        Ok(())
    }

    #[tokio::test]
    async fn unknown_command_has_exact_error_and_is_a_no_op() -> TestResult {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        let (_, before) = request(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        let command = "interface Bridge0 nonsense-arg";
        let (_, answer) = request(
            &app,
            Method::POST,
            "/rci/",
            Some(&cookie),
            Body::from(json!({"parse": command}).to_string()),
        )
        .await?;
        assert_eq!(
            serde_json::from_str::<Value>(&answer)?,
            json!({"status":[{"status":"error","code":"7405600","ident":"Command::Base","message":format!("no such command: {command}")}]})
        );
        let (_, after) = request(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(after, before);
        Ok(())
    }

    #[tokio::test]
    async fn upload_takes_effect_after_reboot() -> TestResult {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        let uploaded = "interface Bridge0\n description \"Uploaded LAN\"\n ip address 192.0.2.1 255.255.255.0\n!\n";
        let (status, _) = request(
            &app,
            Method::PUT,
            "/fui/startup-config.txt",
            Some(&cookie),
            Body::from(uploaded),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        let (_, running_before) = request(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert!(!running_before.contains("Uploaded LAN"));
        drop(
            request(
                &app,
                Method::POST,
                "/rci/",
                Some(&cookie),
                Body::from(json!({"parse":"system reboot"}).to_string()),
            )
            .await?,
        );
        let new_cookie = login(&app, fake.realm()).await?;
        let (_, running_after) = request(
            &app,
            Method::GET,
            "/ci/running-config.txt",
            Some(&new_cookie),
            Body::empty(),
        )
        .await?;
        assert!(running_after.contains("Uploaded LAN"));
        Ok(())
    }
}
