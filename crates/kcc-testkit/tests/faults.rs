//! Public HTTP tests for bounded faults and sanitized observability.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use axum::http::Method;
    use kcc_rci::{
        OutboundPolicy, RciBody, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    };
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile,
    };
    use secrecy::SecretString;
    use serde_json::{Value, json};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// Builds a spawned router, handle, and authenticated client.
    async fn spawned(faults: FaultInjection) -> TestResult<(kcc_testkit::Handle, RciClient)> {
        let fake = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?;
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let router = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let client = RciClient::connect_with(router, credentials, options).await?;
        Ok((handle, client))
    }

    /// Extracts a JSON response body.
    fn json_body(body: RciBody) -> TestResult<Value> {
        match body {
            RciBody::Json(response) => Ok(response.value),
            RciBody::Text(_) => Err("expected JSON response".into()),
            _ => Err("unsupported response body".into()),
        }
    }

    /// A bounded parser fault rejects only matching lines, preserves state, then expires.
    #[tokio::test]
    async fn parse_match_fault_is_bounded_and_non_mutating() -> TestResult {
        let faults = FaultInjection::default().fail_parse_matching("Bridge9 description", 1);
        let (handle, client) = spawned(faults).await?;
        let before = handle.running_config_text();

        let first = client.parse("interface Bridge9 description blocked").await;
        let unrelated = client
            .parse("interface Bridge8 description accepted")
            .await?;
        let later = client
            .parse("interface Bridge9 description accepted")
            .await?;

        assert!(
            first.is_err(),
            "injected RCI status is surfaced as an error"
        );
        assert!(matches!(unrelated, RciBody::Json(_)));
        assert!(matches!(later, RciBody::Json(_)));
        let running = handle.running_config_text();
        assert!(!running.contains("description blocked"));
        assert!(running.contains("interface Bridge8"));
        assert!(running.contains("interface Bridge9"));
        assert_ne!(running, before);
        handle.shutdown().await?;
        Ok(())
    }

    /// The one-shot route-wipe incident clears all routes and reports its safety marker.
    #[tokio::test]
    async fn route_wipe_fault_clears_all_static_routes_once() -> TestResult {
        let faults = FaultInjection::default().route_wipe_on_remove(true);
        let (handle, client) = spawned(faults).await?;
        drop(
            client
                .parse("ip route 198.51.100.0 255.255.255.0 192.0.2.2")
                .await?,
        );
        drop(
            client
                .parse("ip route 203.0.113.0 255.255.255.0 192.0.2.3")
                .await?,
        );

        let response = client
            .post_root(&json!({"parse":"no ip route 198.51.100.0 255.255.255.0 192.0.2.2"}))
            .await?;

        let answer = json_body(response)?;
        assert_eq!(
            answer.pointer("/status/0/message"),
            Some(&json!("cleared all routes."))
        );
        assert!(!handle.running_config_text().contains("ip route "));
        drop(
            client
                .parse("ip route 198.51.100.0 255.255.255.0 192.0.2.2")
                .await?,
        );
        drop(
            client
                .parse("ip route 203.0.113.0 255.255.255.0 192.0.2.3")
                .await?,
        );
        drop(
            client
                .parse("no ip route 198.51.100.0 255.255.255.0 192.0.2.2")
                .await?,
        );
        let running = handle.running_config_text();
        assert!(!running.contains("198.51.100.0"));
        assert!(running.contains("203.0.113.0"));
        handle.shutdown().await?;
        Ok(())
    }

    /// Request records retain only method, path, and sorted query pairs.
    #[tokio::test]
    async fn request_log_excludes_headers_bodies_and_secrets() -> TestResult {
        let (handle, client) = spawned(FaultInjection::default()).await?;
        let secret = "request-body-secret";
        drop(
            client
                .post_root(&json!({"parse":format!("user tester password plain {secret}")}))
                .await?,
        );
        let path = kcc_rci::RciPath::from_segments(["show", "interface"])?;
        drop(client.get(&path, &[("z", "2"), ("a", "1")]).await?);

        let records = handle.request_log();
        let interface = records
            .iter()
            .find(|record| record.path() == "/rci/show/interface")
            .ok_or("missing interface request")?;
        assert_eq!(interface.method(), &Method::GET);
        assert_eq!(
            interface.query(),
            &[
                ("a".to_owned(), "1".to_owned()),
                ("z".to_owned(), "2".to_owned())
            ]
        );
        let serialized = format!("{records:?}");
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains(DEFAULT_PASSWORD));
        assert!(!serialized.contains("Cookie"));
        assert!(!serialized.contains("Authorization"));
        let record_count = u64::try_from(records.len())?;
        assert_eq!(handle.request_count(), record_count);
        handle.shutdown().await?;
        Ok(())
    }

    /// Handle snapshots expose independent settings, running, and startup stores.
    #[tokio::test]
    async fn handle_snapshots_track_independent_stores() -> TestResult {
        let (handle, client) = spawned(FaultInjection::default()).await?;
        let settings_before = handle.settings_snapshot();
        let startup_before = handle.startup_config_text();

        drop(
            client
                .parse("interface Bridge7 description transient")
                .await?,
        );

        assert_eq!(handle.settings_snapshot(), settings_before);
        assert_eq!(handle.startup_config_text(), startup_before);
        assert!(
            handle
                .running_config_text()
                .contains("description transient")
        );
        handle.shutdown().await?;
        Ok(())
    }
}
