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

    #[tokio::test]
    async fn bridge_membership_rejects_unknown_interfaces() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;

        for keyword in ["include", "inherit"] {
            let command = format!("interface Bridge0 {keyword} MissingInterface0");
            let reply = send(
                &app,
                Method::POST,
                "/rci/",
                Some(&cookie),
                Body::from(json!({"parse": command}).to_string()),
            )
            .await?
            .json()?;

            assert_eq!(reply.pointer("/status/0/status"), Some(&json!("error")));
            assert_eq!(
                reply.pointer("/status/0/message"),
                Some(&json!("interface not found."))
            );
        }
        Ok(())
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

    /// CLI mutations are observable through ordinary show and running/startup projections.
    #[tokio::test]
    async fn cli_mutations_project_through_show_surfaces() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let commands = [
            "known host blocked 02:00:00:00:00:99",
            "ip hotspot host 02:00:00:00:00:99 deny",
            "ip hotspot host 02:00:00:00:00:99 policy Policy9",
            "ip dhcp host 02:00:00:00:00:98 192.0.2.98",
            "ip route 198.51.100.0 255.255.255.0 192.0.2.254",
            "ip static tcp ISP 443 192.0.2.44 8443",
            "ip nat ISP",
            "access-list test permit tcp",
            "service ssh",
            "user operator password plain top-secret-password",
            "user operator tag cli",
            "dns-proxy tls upstream 192.0.2.53 853 sni dns.example.invalid",
            "dns-proxy https upstream https://dns.example.invalid/dns-query",
            "interface WifiMaster0/AccessPoint0 ssid changed-ssid",
            "interface WifiMaster0/AccessPoint0 authentication wpa-psk plain-text-psk",
        ];
        for command in commands {
            let body = json!({"parse":command}).to_string();
            let reply = send(&app, Method::POST, "/rci/", Some(&cookie), Body::from(body)).await?;
            assert_eq!(reply.status, StatusCode::OK, "{command}");
            assert_eq!(
                reply.json()?.pointer("/status/0/status"),
                Some(&json!("message")),
                "{command}"
            );
        }

        let hotspot = send(
            &app,
            Method::GET,
            "/rci/show/ip/hotspot",
            Some(&cookie),
            Body::empty(),
        )
        .await?
        .json()?;
        assert!(
            hotspot
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| {
                    row.get("mac") == Some(&json!("02:00:00:00:00:99"))
                        && row.get("name") == Some(&json!("blocked"))
                        && row.get("registered") == Some(&json!(true))
                        && row.get("access") == Some(&json!("deny"))
                        && row.get("policy") == Some(&json!("Policy9"))
                }))
        );
        let bindings = send(
            &app,
            Method::GET,
            "/rci/show/ip/dhcp/bindings",
            Some(&cookie),
            Body::empty(),
        )
        .await?
        .json()?;
        assert!(bindings.to_string().contains("192.0.2.98"));
        let routes = send(
            &app,
            Method::GET,
            "/rci/show/ip/route",
            Some(&cookie),
            Body::empty(),
        )
        .await?
        .json()?;
        assert!(routes.to_string().contains("198.51.100.0"));

        assert_projected_configuration(&app, &cookie).await?;
        Ok(())
    }

    /// Checks mutable running projections and startup isolation.
    async fn assert_projected_configuration(app: &Router, cookie: &str) -> TestResult {
        let requested = json!({"show":{"rc":{
            "ip":{"dhcp":{"host":{}},"route":{},"static":{},"nat":{}},
            "dns-proxy":{},"user":{},"service":{},"access-list":{},"interface":{}
        }}});
        let running = send(
            app,
            Method::POST,
            "/rci/",
            Some(cookie),
            Body::from(requested.to_string()),
        )
        .await?
        .json()?;
        let serialized = running.to_string();
        for expected in [
            "192.0.2.98",
            "198.51.100.0",
            "8443",
            "operator",
            "dns.example.invalid",
            "changed-ssid",
        ] {
            assert!(
                serialized.contains(expected),
                "missing {expected}: {running}"
            );
        }
        assert!(!serialized.contains("top-secret-password"));
        assert!(!serialized.contains("plain-text-psk"));
        assert_eq!(
            running
                .pointer("/show/rc/interface/WifiMaster0~1AccessPoint0/authentication/wpa-psk/ns3"),
            Some(&json!(true))
        );

        let startup_request = json!({"show":{"sc":{"ip":{"dhcp":{"host":{}}}}}});
        let startup = send(
            app,
            Method::POST,
            "/rci/",
            Some(cookie),
            Body::from(startup_request.to_string()),
        )
        .await?
        .json()?;
        assert_eq!(startup.pointer("/show/sc/ip/dhcp/host"), Some(&json!([])));
        Ok(())
    }

    /// WireGuard show projection exposes peer operation while redacting all secret values.
    #[tokio::test]
    async fn wireguard_projection_never_returns_secret_keys() -> TestResult {
        let (fake, app) = ultra()?;
        let cookie = login(&app, fake.realm()).await?;
        let private_key = "private-key-material";
        let preshared_key = "preshared-key-material";
        let commands = [
            "interface Wireguard0",
            &format!("interface Wireguard0 wireguard private-key {private_key}"),
            "interface Wireguard0 wireguard listen-port 51820",
            "interface Wireguard0 wireguard peer peer-public-key",
            "interface Wireguard0 wireguard peer peer-public-key endpoint 198.51.100.44 51820",
            "interface Wireguard0 wireguard peer peer-public-key allow-ips 192.0.2.0 255.255.255.0",
            "interface Wireguard0 wireguard peer peer-public-key keepalive-interval 25",
            &format!(
                "interface Wireguard0 wireguard peer peer-public-key preshared-key {preshared_key}"
            ),
        ];
        for command in commands {
            let reply = send(
                &app,
                Method::POST,
                "/rci/",
                Some(&cookie),
                Body::from(json!({"parse":command}).to_string()),
            )
            .await?;
            assert_eq!(
                reply.json()?.pointer("/status/0/status"),
                Some(&json!("message"))
            );
        }

        let shown = send(
            &app,
            Method::POST,
            "/rci/show/interface",
            Some(&cookie),
            Body::from(json!({"name":"Wireguard0"}).to_string()),
        )
        .await?
        .json()?;
        let serialized = shown.to_string();
        assert_eq!(shown.pointer("/type"), Some(&json!("Wireguard")), "{shown}");
        assert_eq!(shown.pointer("/listen-port"), Some(&json!("51820")));
        assert_eq!(
            shown.pointer("/peers/peer-public-key/keepalive-interval"),
            Some(&json!(["25"]))
        );
        assert_eq!(
            shown.pointer("/peers/peer-public-key/preshared-key/present"),
            Some(&json!(true))
        );
        assert!(!serialized.contains(private_key));
        assert!(!serialized.contains(preshared_key));
        Ok(())
    }
}
