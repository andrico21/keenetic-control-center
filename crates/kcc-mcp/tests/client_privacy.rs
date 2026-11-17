//! `redact_clients_in_mcp` over a real session: what a client sees in results and in the
//! progress notifications of a running tool.
extern crate alloc;

#[expect(
    dead_code,
    reason = "the shared MCP session support; this suite needs part of it"
)]
#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the privacy contract"
)]
mod tests {
    use kcc_app::settings::PrivacyConfig;
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use super::lab::{Lab, TestResult, admin};

    /// E-05: with `redact_clients_in_mcp` on, the progress messages of a running diagnostic
    /// pass through the pseudonymizer: no address of the router's reply reaches the client.
    #[tokio::test]
    async fn progress_messages_are_pseudonymized() -> TestResult {
        let mut privacy = PrivacyConfig::default();
        privacy.redact_clients_in_mcp = true;
        let mut lab = Lab::start_with_privacy(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            true,
            privacy,
        )
        .await?;
        let started = lab
            .call(
                "kcc_diagnostics_write",
                json!({"host": "lab-1", "op": "traceroute", "arguments": {"host": "192.0.2.1"}}),
                true,
            )
            .await?;
        assert_eq!(started.value()?.get("status"), Some(&json!("completed")));
        let messages: Vec<String> = lab
            .progress_received()
            .await
            .into_iter()
            .filter_map(|progress| progress.message)
            .collect();
        assert!(!messages.is_empty(), "no progress notification arrived");
        assert!(
            messages
                .iter()
                .all(|message| !message.contains("192.0.2.") && !message.contains("198.51.100.")),
            "{messages:?}"
        );
        lab.stop().await
    }
}
