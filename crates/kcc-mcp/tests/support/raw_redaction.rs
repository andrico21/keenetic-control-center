//! Raw router output redaction through the MCP session boundary.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the raw MCP secret boundary"
)]
mod tests {
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// Raw interface output masks secret fields even when the caller can write them.
    // NOT cancel-safe: the fixture owns router and MCP tasks until explicit shutdown.
    #[tokio::test]
    async fn raw_interface_read_redacts_planted_secret() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let secret = ["dummy", "runtime", "wifi", "credential"].join("-");
        let planted = lab
            .call(
                "kcc_wifi_write",
                json!({
                    "host":"lab-1", "op":"wpa_psk", "name":"WifiMaster0/AccessPoint0",
                    "secret":secret
                }),
                false,
            )
            .await?;
        assert_eq!(planted.value()?.get("applied"), Some(&json!(true)));
        let reply = lab
            .call(
                "kcc_rci_read",
                json!({
                    "host":"lab-1", "catalog_path":"show interface", "path":["show","interface"]
                }),
                false,
            )
            .await?;
        let value = reply.value()?;
        assert_eq!(
            value.pointer("/value/WifiMaster0~1AccessPoint0/authentication/wpa-psk"),
            Some(&json!("<redacted>"))
        );
        assert!(
            !value.to_string().contains(&secret),
            "secret never reaches MCP output"
        );
        lab.stop().await
    }
}
