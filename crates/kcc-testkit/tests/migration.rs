//! Opt-in migration scenario protocol contracts.
extern crate alloc;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::assertions_on_result_states,
    reason = "integration assertions establish simulator behavior"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, str::FromStr as _, time::Duration};

    use kcc_rci::{
        OutboundPolicy, RciBody, RciClient, RciClientOptions, RciPath, RouterUrl, auth::Credentials,
    };
    use kcc_testkit::{FakeRouter, migration::Fixture, model::Profile, time::MockClock};
    use secrecy::SecretString;
    use serde_json::Value;

    /// Agreement state changes only after accept, mode is explicit, and NS3 input can be rejected.
    // NOT cancel-safe: mutates an isolated router.
    #[tokio::test]
    async fn agreements_mode_and_secret_rejection_are_opt_in() -> Result<(), Box<dyn Error>> {
        let mut scenario = Fixture::default();
        scenario.mode = Some("ap".to_owned());
        scenario.agreements_required = true;
        scenario.reject_ns3 = true;
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let client = connect(address.to_string()).await?;
        for agreement in ["dpn", "eula"] {
            let path = RciPath::from_segments(["show", agreement, "list"])?;
            assert_eq!(
                value(client.get(&path, &()).await?)?.get("accepted"),
                Some(&Value::Bool(false))
            );
            let document = RciPath::from_segments(["show", agreement, "document"])?;
            assert!(
                value(client.get(&document, &()).await?)?
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some()
            );
            drop(client.parse(&format!("{agreement} accept")).await?);
            assert_eq!(
                value(client.get(&path, &()).await?)?.get("accepted"),
                Some(&Value::Bool(true))
            );
        }
        let mode = RciPath::from_segments(["show", "system", "mode"])?;
        assert_eq!(
            value(client.get(&mode, &()).await?)?
                .get("active")
                .and_then(Value::as_str),
            Some("ap")
        );
        let before = handle.running_config_text();
        assert!(
            client
                .parse("interface Bridge9 authentication password ns3 encoded")
                .await
                .is_err()
        );
        assert_eq!(handle.running_config_text(), before);
        handle.shutdown().await?;
        Ok(())
    }

    /// A request after clock-driven loss observes the router's rollback, without a sleep.
    // NOT cancel-safe: mutates an isolated router.
    #[tokio::test]
    async fn injected_loss_expires_fail_safe_before_connectivity_returns()
    -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(MockClock::new());
        let mut scenario = Fixture::default();
        scenario.loss_until = Some(Duration::from_secs(301));
        let (address, handle) = FakeRouter::builder(Profile::default())
            .clock(Arc::<MockClock>::clone(&clock))
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let client = connect(address.to_string()).await?;
        drop(
            client
                .parse("system configuration fail-safe timer reboot 300")
                .await?,
        );
        drop(
            client
                .parse("interface Bridge9 description temporary")
                .await?,
        );
        let path = RciPath::from_segments(["show", "last-change"])?;
        assert!(client.get(&path, &()).await.is_err());
        clock.advance(Duration::from_secs(301));
        assert_eq!(
            value(client.get(&path, &()).await?)?.get("unsaved"),
            Some(&Value::Bool(false))
        );
        assert!(!handle.running_config_text().contains("temporary"));
        handle.shutdown().await?;
        Ok(())
    }

    /// Builds a loopback-only test client.
    // cancel-safe: creates transport without writes.
    async fn connect(host: String) -> Result<RciClient, Box<dyn Error>> {
        Ok(RciClient::connect_with(
            RouterUrl::from_str(&format!("http://{host}"))?,
            Credentials::new("admin".to_owned(), SecretString::from("admin".to_owned())),
            RciClientOptions::default()
                .with_outbound(OutboundPolicy::default().with_loopback(true)),
        )
        .await?)
    }

    /// Extracts the JSON body expected by these protocol endpoints.
    fn value(body: RciBody) -> Result<Value, Box<dyn Error>> {
        match body {
            RciBody::Json(response) => Ok(response.value),
            RciBody::Text(_) | _ => Err("expected JSON".into()),
        }
    }
}
