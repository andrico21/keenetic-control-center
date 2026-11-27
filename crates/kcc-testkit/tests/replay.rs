//! Replaying captured answers: continued exchanges and verbatim `show` and `show rc` reads.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_rci::{
        OutboundPolicy, RciBody, RciClient, RciClientOptions, RciError, RciPath, RouterUrl,
        auth::Credentials,
    };
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
    use secrecy::SecretString;
    use serde_json::{Value, json};

    /// Fallible test result.
    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    /// The JSON value of an answer.
    fn json(body: RciBody) -> TestResult<Value> {
        match body {
            RciBody::Json(response) => Ok(response.value),
            RciBody::Text(_) => Err("expected a JSON answer".into()),
            _ => Err("unsupported answer".into()),
        }
    }

    /// A client with its own router session.
    async fn client(address: SocketAddr) -> TestResult<RciClient> {
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let router = RouterUrl::from_str(&format!("http://{address}"))?;
        Ok(RciClient::connect_with(router, credentials, options).await?)
    }

    /// Three answers of one continued exchange.
    fn chunks() -> [Value; 3] {
        [
            json!({"continued": true, "message": "first"}),
            json!({"continued": true, "message": "second"}),
            json!({"message": "third"}),
        ]
    }

    /// Todo 12: a POST starts the captured exchange, each `GET` of the same path in the
    /// same session reads the next answer, and the last answer repeats.
    #[tokio::test]
    async fn a_continued_fixture_answers_in_order_within_one_session() -> TestResult {
        let fake = FakeRouter::builder(Profile::default())
            .continued_fixture("tools/ping", chunks().to_vec())
            .build()?;
        let (address, _handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let session = client(address).await?;
        let path = RciPath::from_segments(["tools", "ping"])?;

        let started = json(session.post(&path, &json!({"host": "192.0.2.1"})).await?)?;
        let second = json(session.get(&path, &()).await?)?;
        let third = json(session.get(&path, &()).await?)?;
        let after = json(session.get(&path, &[("id", "1")]).await?)?;

        let [first, next, last] = chunks();
        assert_eq!(
            [started, second, third, after],
            [first, next, last.clone(), last]
        );
        Ok(())
    }

    /// Todo 12: another session starts the exchange from its first answer again, and a
    /// session that never started it reads nothing.
    #[tokio::test]
    async fn another_session_starts_the_continued_fixture_from_the_first_answer() -> TestResult {
        let fake = FakeRouter::builder(Profile::default())
            .continued_fixture("components/list", chunks().to_vec())
            .build()?;
        let (address, _handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let path = RciPath::from_segments(["components", "list"])?;
        let first = client(address).await?;
        let second = client(address).await?;

        drop(json(first.post(&path, &json!({})).await?)?);
        drop(json(first.get(&path, &()).await?)?);
        let restarted = json(second.post(&path, &json!({})).await?)?;
        let next = json(second.get(&path, &()).await?)?;
        let idle = client(address).await?;
        let unstarted = idle.get(&path, &()).await;

        let [opening, following, _] = chunks();
        assert_eq!(restarted, opening);
        assert_eq!(next, following);
        assert!(
            matches!(unstarted, Err(RciError::NotFound)),
            "a GET without a POST in its session reads nothing: {unstarted:?}"
        );
        Ok(())
    }

    /// Todo 12: a string answer of a continued fixture is answered as plain text, as the
    /// capture records a text answer.
    #[tokio::test]
    async fn a_string_answer_of_a_continued_fixture_is_text() -> TestResult {
        let fake = FakeRouter::builder(Profile::default())
            .continued_fixture("show/log", vec![Value::String("log line\n".to_owned())])
            .build()?;
        let (address, _handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let session = client(address).await?;
        let path = RciPath::from_segments(["show", "log"])?;

        let answer = session.post(&path, &json!({"max-lines": 20_u8})).await?;

        assert!(
            matches!(&answer, RciBody::Text(text) if text == "log line\n"),
            "{answer:?}"
        );
        Ok(())
    }

    /// Todo 12: a replayed router answers each `show` fixture exactly as given (no
    /// running-configuration rows mixed in), a `show` read without a fixture with 404, and
    /// `show rc` only from its `rc_fixture` roots.
    #[tokio::test]
    async fn a_replayed_router_answers_only_its_fixtures_verbatim() -> TestResult {
        let hotspot = json!({"host": [{"mac": "02:00:00:00:00:01", "name": "host-1"}]});
        let users = json!({"admin": {"tag": ["cli"]}});
        let fake = FakeRouter::builder(Profile::default())
            .show_fixture("ip/hotspot", hotspot.clone())
            .rc_fixture("/user", users.clone())
            .replayed()
            .build()?;
        let (address, _handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let session = client(address).await?;

        let shown = json(
            session
                .get(&RciPath::from_segments(["show", "ip", "hotspot"])?, &())
                .await?,
        )?;
        let absent = session
            .get(&RciPath::from_segments(["show", "ip", "route"])?, &())
            .await;
        let rc = session
            .show_rc(json!({"user": {}, "service": {}}))
            .await?
            .configuration_tree()
            .clone();

        assert_eq!(shown, hotspot);
        assert!(matches!(absent, Err(RciError::NotFound)), "{absent:?}");
        assert_eq!(rc, json!({"user": users}));
        Ok(())
    }
}
