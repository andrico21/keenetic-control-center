//! The fake router's `show rc` bridge membership agrees with its configuration text.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_config::config_text::{Token, flatten, parse};
    use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
    use secrecy::SecretString;
    use serde_json::Value;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// Builds a spawned default router and authenticated client.
    async fn spawned() -> TestResult<(kcc_testkit::Handle, RciClient)> {
        let fake = FakeRouter::builder(Profile::default()).build()?;
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

    /// Every show-rc membership edge is represented by the running configuration text.
    // NOT cancel-safe: the fixture owns router tasks until shutdown.
    #[tokio::test]
    async fn bridge_membership_text_agrees_with_show_rc() -> TestResult {
        let (handle, client) = spawned().await?;
        let response = client.show_rc(serde_json::json!({"interface":{}})).await?;
        let interfaces = response
            .configuration_tree()
            .get("interface")
            .and_then(Value::as_object)
            .ok_or("interface tree")?;
        let text = handle.running_config_text();
        let ast = parse(&text)?;
        let lines = flatten(&ast);
        let mut count = 0_usize;
        for (bridge, fields) in interfaces {
            for keyword in ["include", "inherit"] {
                for member in fields
                    .get(keyword)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = member
                        .get("interface")
                        .and_then(Value::as_str)
                        .ok_or("member")?;
                    let expected = ["interface", bridge, keyword, name];
                    assert!(
                        lines.iter().any(|line| line
                            .tokens
                            .iter()
                            .filter_map(|token| match token {
                                Token::Word(word) => Some(word.as_str()),
                                Token::Ns3(_) | _ => None,
                            })
                            .eq(expected)),
                        "missing membership {expected:?}"
                    );
                    count = count.saturating_add(1);
                }
            }
        }
        assert_eq!(count, 5, "default bridge members");
        assert_eq!(handle.running_config_text(), handle.startup_config_text());
        handle.shutdown().await?;
        Ok(())
    }
}
