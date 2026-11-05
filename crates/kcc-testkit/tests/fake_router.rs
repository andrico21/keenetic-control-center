//! Integration tests for the fake router, driven in-process through the axum router.

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
        body::{Body, Bytes, to_bytes},
        http::{HeaderMap, Method, Request, StatusCode, header},
    };
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, MAX_BODY_BYTES,
        model::{Firmware, Model, Profile},
        ndw2,
        time::{Clock, MockClock},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    /// Result type of the tests.
    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// One response, fully read.
    struct Reply {
        /// Status code.
        status: StatusCode,
        /// Response headers.
        headers: HeaderMap,
        /// Response body.
        body: Bytes,
    }

    impl Reply {
        /// The header `name` as text, or an empty string.
        fn header(&self, name: &str) -> &str {
            self.headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
        }

        /// The body as JSON.
        fn json(&self) -> TestResult<Value> {
            Ok(serde_json::from_slice(&self.body)?)
        }
    }

    /// Sends one request to `app`.
    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        request_body: Body,
    ) -> TestResult<Reply> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(value) = cookie {
            builder = builder.header(header::COOKIE, value);
        }
        let request = builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(request_body)?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok(Reply {
            status,
            headers,
            body,
        })
    }

    /// Opens a session: returns the `Cookie` header value and the challenge.
    async fn challenge(app: &Router) -> TestResult<(String, String)> {
        let reply = send(app, Method::GET, "/auth", None, Body::empty()).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let cookie = reply
            .header("set-cookie")
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        Ok((cookie, reply.header("x-ndm-challenge").to_owned()))
    }

    /// Logs in as the default user; returns the `Cookie` header value.
    async fn login(app: &Router, realm: &str) -> TestResult<String> {
        let (cookie, token) = challenge(app).await?;
        let password = ndw2::response(DEFAULT_LOGIN, realm, DEFAULT_PASSWORD, &token);
        let body = json!({"login": DEFAULT_LOGIN, "password": password}).to_string();
        let reply = send(app, Method::POST, "/auth", Some(&cookie), Body::from(body)).await?;
        assert_eq!(reply.status, StatusCode::OK, "login with the correct hash");
        Ok(cookie)
    }

    /// The default `KN-1811` 5.1 router and its axum app.
    fn ultra() -> TestResult<(FakeRouter, Router)> {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let app = fake.router();
        Ok((fake, app))
    }

    /// A 401 carries every ndw2 header, and the cookie name differs per server.
    #[tokio::test]
    async fn challenge_headers_and_random_cookie_name() -> TestResult {
        let (fake, app) = ultra()?;
        let (other, _) = ultra()?;
        assert_ne!(
            fake.cookie_name(),
            other.cookie_name(),
            "cookie name is per server"
        );
        assert!(
            fake.cookie_name()
                .bytes()
                .all(|byte| byte.is_ascii_uppercase()),
            "cookie name is uppercase"
        );

        let reply = send(&app, Method::GET, "/auth", None, Body::empty()).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let token = reply.header("x-ndm-challenge");
        assert_eq!(token.len(), 32);
        assert_eq!(reply.header("x-ndm-realm"), "Keenetic Ultra");
        assert_eq!(reply.header("x-ndm-product"), "Titan");
        let cookie = reply.header("set-cookie");
        let (pair, attributes) = cookie.split_once("; ").unwrap_or_default();
        let (name, session_id) = pair.split_once('=').unwrap_or_default();
        assert_eq!(name, fake.cookie_name());
        assert_eq!(attributes, "Path=/; SameSite=Strict; Max-Age=300");
        assert_eq!(
            reply.header("www-authenticate"),
            format!(
                "x-ndw2-interactive realm=\"Keenetic Ultra\" challenge=\"{token}\" session_id=\"{session_id}\" session_cookie=\"{name}\""
            )
        );
        Ok(())
    }

    /// A wrong hash is refused and the session stays unauthenticated.
    #[tokio::test]
    async fn wrong_hash_is_refused() -> TestResult {
        let (_, app) = ultra()?;
        let (cookie, _) = challenge(&app).await?;
        let body = json!({"login": "admin", "password": "00"}).to_string();
        let reply = send(&app, Method::POST, "/auth", Some(&cookie), Body::from(body)).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let reply_2 = send(
            &app,
            Method::GET,
            "/rci/show/version",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply_2.status, StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// The correct hash logs in, then `show version` answers with the profile.
    #[tokio::test]
    async fn correct_hash_then_show_version() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let reply = send(&app, Method::GET, "/auth", Some(&cookie), Body::empty()).await?;
        assert_eq!(reply.status, StatusCode::OK);
        let reply_2 = send(
            &app,
            Method::GET,
            "/rci/show/version",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply_2.status, StatusCode::OK);
        let version = reply_2.json()?;
        assert_eq!(version.get("hw_id"), Some(&json!("KN-1811")));
        assert_eq!(version.get("title"), Some(&json!("5.1.3")));
        Ok(())
    }

    /// Requests without a session, and after logout, get 401.
    #[tokio::test]
    async fn rci_requires_session() -> TestResult {
        let (fake, app) = ultra()?;
        let reply = send(&app, Method::GET, "/rci/show/version", None, Body::empty()).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let cookie = login(&app, fake.realm()).await?;
        let reply_2 = send(&app, Method::DELETE, "/auth", Some(&cookie), Body::empty()).await?;
        assert_eq!(reply_2.status, StatusCode::OK);
        let reply_3 = send(&app, Method::GET, "/rci/", Some(&cookie), Body::empty()).await?;
        assert_eq!(reply_3.status, StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// An idle session expires after the TTL on the injected clock.
    #[tokio::test]
    async fn session_expires_after_ttl() -> TestResult {
        let clock = Arc::new(MockClock::new());
        let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
        let fake = FakeRouter::builder(Profile::default())
            .clock(injected)
            .build()?;
        let app = fake.router();
        let cookie = login(&app, fake.realm()).await?;
        clock.advance(Duration::from_secs(299));
        let reply = send(
            &app,
            Method::GET,
            "/rci/show/version",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply.status, StatusCode::OK, "still inside the TTL");
        clock.advance(Duration::from_secs(301));
        let reply_2 = send(
            &app,
            Method::GET,
            "/rci/show/version",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(
            reply_2.status,
            StatusCode::UNAUTHORIZED,
            "expired after the TTL"
        );
        Ok(())
    }

    /// A body of only unknown fields answers `{}` and changes nothing.
    #[tokio::test]
    async fn unknown_field_answers_empty_object() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let before = fake.settings();
        let body = json!({"system": {"no-such-field": "x"}}).to_string();
        let reply = send(&app, Method::POST, "/rci/", Some(&cookie), Body::from(body)).await?;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()?, json!({}));
        assert_eq!(fake.settings(), before);
        Ok(())
    }

    /// A known field is written, mirrored with a status, and readable back.
    #[tokio::test]
    async fn known_field_is_written() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let body =
            json!([{"system": {"name": "renamed"}}, {"show": {"rc": {"system": {"name": {}}}}}]);
        let reply = send(
            &app,
            Method::POST,
            "/rci/",
            Some(&cookie),
            Body::from(body.to_string()),
        )
        .await?;
        let answer = reply.json()?;
        assert!(
            answer.pointer("/0/system/name/status/0/message").is_some(),
            "{answer}"
        );
        assert_eq!(
            answer.pointer("/1/show/rc/system/name"),
            Some(&json!("renamed"))
        );
        Ok(())
    }

    /// `"no": true` and `DELETE ?mac=` remove array members.
    #[tokio::test]
    async fn no_and_delete_remove() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let uri = "/rci/ip/hotspot/host?mac=02:00:00:00:11:01";
        let reply = send(&app, Method::GET, uri, Some(&cookie), Body::empty()).await?;
        assert_eq!(reply.json()?.get("policy"), Some(&json!("Policy0")));
        let reply_2 = send(&app, Method::DELETE, uri, Some(&cookie), Body::empty()).await?;
        assert_eq!(reply_2.status, StatusCode::OK);
        let reply_3 = send(&app, Method::GET, uri, Some(&cookie), Body::empty()).await?;
        assert_eq!(reply_3.status, StatusCode::NOT_FOUND);
        let body = json!({"mac": "02:00:00:00:11:02", "no": true}).to_string();
        let reply_4 = send(
            &app,
            Method::POST,
            "/rci/ip/hotspot/host",
            Some(&cookie),
            Body::from(body),
        )
        .await?;
        assert!(reply_4.json()?.get("status").is_some(), "status answer");
        assert_eq!(
            fake.settings().pointer("/ip/hotspot/host"),
            Some(&json!([]))
        );
        Ok(())
    }

    /// An unknown show path is 404 with an empty body.
    #[tokio::test]
    async fn unknown_show_is_404_empty() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let reply = send(
            &app,
            Method::GET,
            "/rci/show/no-such-thing",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert!(reply.body.is_empty(), "404 body is empty");
        Ok(())
    }

    /// `POST /rci` without the trailing slash is 405.
    #[tokio::test]
    async fn rci_without_trailing_slash_is_405() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let reply = send(&app, Method::POST, "/rci", Some(&cookie), Body::from("{}")).await?;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }

    /// A body over 1 MiB is 413.
    #[tokio::test]
    async fn body_over_one_mib_is_413() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let filler = "x".repeat(MAX_BODY_BYTES);
        let body = json!({"system": {"description": filler}}).to_string();
        let reply = send(&app, Method::POST, "/rci/", Some(&cookie), Body::from(body)).await?;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    /// Documentation-derived profiles report their firmware and lack 5.1-only settings.
    #[tokio::test]
    async fn derived_profile() -> TestResult {
        let fake = FakeRouter::builder(Profile::new(Model::Kn3810, Firmware::V4_3)?).build()?;
        let app = fake.router();
        let cookie = login(&app, "Keenetic Hopper").await?;
        let reply = send(
            &app,
            Method::GET,
            "/rci/show/version",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply.json()?.get("title"), Some(&json!("4.3.9")));
        let reply_2 = send(
            &app,
            Method::GET,
            "/rci/ipv6/access-list",
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(reply_2.status, StatusCode::NOT_FOUND);
        Ok(())
    }

    /// The spawned server answers over TCP and shuts down.
    #[tokio::test]
    async fn spawn_and_shutdown() -> TestResult {
        let (addr, handle) = FakeRouter::spawn().await?;
        assert!(addr.ip().is_loopback(), "binds loopback");
        handle.shutdown().await?;
        Ok(())
    }

    /// Every diagnostics endpoint preserves its process kind and returns its canned reply.
    #[tokio::test]
    async fn diagnostic_process_kinds_complete_with_distinct_replies() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let cases = [
            ("ping", json!([1_u8, 2_u8, 3_u8])),
            ("ping6", json!(["2001:db8::1", "2001:db8::1"])),
            (
                "traceroute",
                json!([
                    {"hop":1_u8,"address":"192.0.2.1"},
                    {"hop":2_u8,"address":"198.51.100.1"}
                ]),
            ),
            (
                "arping",
                json!([{"address":"192.0.2.1","mac":"02:00:00:00:00:01"}]),
            ),
            ("iperf3", json!({"bits_per_second":100_000_000_u64})),
        ];

        for (kind, expected_reply) in cases {
            let path = format!("/rci/tools/{kind}");
            let started = send(&app, Method::POST, &path, Some(&cookie), Body::from("{}"))
                .await?
                .json()?;
            assert_eq!(started.pointer("/process/kind"), Some(&json!(kind)));
            let id = started
                .pointer("/process/id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let poll_path = format!("{path}?id={id}");
            for _poll in 0_u8..3_u8 {
                let running = send(&app, Method::GET, &poll_path, Some(&cookie), Body::empty())
                    .await?
                    .json()?;
                assert_eq!(running.pointer("/process/kind"), Some(&json!(kind)));
                assert_eq!(running.get("continued"), Some(&json!(true)));
            }
            let completed = send(&app, Method::GET, &poll_path, Some(&cookie), Body::empty())
                .await?
                .json()?;
            assert_eq!(completed.pointer("/process/kind"), Some(&json!(kind)));
            assert_eq!(completed.get("reply"), Some(&expected_reply));
        }
        Ok(())
    }

    /// Poll and stop reject a process id presented at a different diagnostics endpoint.
    #[tokio::test]
    async fn diagnostic_process_ids_are_scoped_to_their_kind() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let started = send(
            &app,
            Method::POST,
            "/rci/tools/ping6",
            Some(&cookie),
            Body::from("{}"),
        )
        .await?
        .json()?;
        let id = started
            .pointer("/process/id")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let wrong_poll = send(
            &app,
            Method::GET,
            &format!("/rci/tools/ping?id={id}"),
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(wrong_poll.status, StatusCode::NOT_FOUND);
        let wrong_stop = send(
            &app,
            Method::DELETE,
            &format!("/rci/tools/traceroute?id={id}"),
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(wrong_stop.status, StatusCode::NOT_FOUND);
        let stopped = send(
            &app,
            Method::DELETE,
            &format!("/rci/tools/ping6?id={id}"),
            Some(&cookie),
            Body::empty(),
        )
        .await?;
        assert_eq!(stopped.status, StatusCode::OK);
        assert_eq!(fake.stopped_processes(), 1);
        Ok(())
    }

    /// Fake-router and server-handle counters expose the same shared request count.
    #[tokio::test]
    async fn request_count_is_shared_by_fake_router_and_handle() -> TestResult {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let app = fake.router();
        let (_, handle) = fake
            .clone()
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        assert_eq!(fake.request_count(), 0);
        assert_eq!(handle.request_count(), 0);

        let reply = send(&app, Method::GET, "/auth", None, Body::empty()).await?;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(fake.request_count(), 1);
        assert_eq!(handle.request_count(), 1);
        handle.shutdown().await?;
        Ok(())
    }
}
