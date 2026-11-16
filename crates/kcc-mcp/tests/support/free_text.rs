//! MCP client, DHCP and firewall writes put free text into router lines as one word.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire contracts"
)]
mod tests {
    use kcc_testkit::{FakeRouter, Handle, model::Profile};
    use serde_json::json;

    use crate::lab::{Lab, TestResult, admin};

    /// The parse commands `router` received that start with `prefix`.
    fn sent(router: &Handle, prefix: &str) -> Vec<String> {
        router
            .request_log()
            .iter()
            .filter_map(|record| record.command())
            .filter(|command| command.starts_with(prefix))
            .map(str::to_owned)
            .collect()
    }

    /// SEC2-02, C-01: `register` sends a name with a space as one quoted word, and an
    /// `access` change on an unregistered client with no `value` is refused instead of
    /// sending `known host  <mac>`.
    #[tokio::test]
    async fn client_names_are_quoted_and_an_empty_one_is_refused() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let registered = lab
            .call(
                "kcc_clients_write",
                json!({"host":"lab-1","op":"register","mac":"02:00:00:00:10:aa","value":"Anna phone"}),
                false,
            )
            .await?;
        assert_eq!(registered.value()?.get("applied"), Some(&json!(true)));
        assert_eq!(
            sent(lab.router("lab-1")?, "known host"),
            ["known host \"Anna phone\" 02:00:00:00:10:aa"]
        );
        let unnamed = lab
            .call(
                "kcc_clients_write",
                json!({"host":"lab-1","op":"access","mac":"02:00:00:00:10:02","permit":false}),
                false,
            )
            .await?;
        assert_eq!(unnamed.error(), Some("validation_failed"));
        assert_eq!(sent(lab.router("lab-1")?, "known host").len(), 1);
        lab.stop().await
    }

    /// C-01: a static-lease `mac` is a MAC address, not text that can carry more words.
    #[tokio::test]
    async fn static_lease_mac_with_words_is_refused() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let reply = lab
            .call(
                "kcc_dhcp_write",
                json!({"host":"lab-1","op":"static_lease","mac":"02:00:00:00:10:02 203.0.113.9","begin":"192.0.2.50"}),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("invalid_arguments"));
        assert_eq!(
            sent(lab.router("lab-1")?, "ip dhcp host"),
            Vec::<String>::new()
        );
        lab.stop().await
    }

    /// N7: an `acl` with spaces is refused before planning, so it can never be classified
    /// against a binding it does not match.
    #[tokio::test]
    async fn firewall_acl_with_spaces_is_refused() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let reply = lab
            .call(
                "kcc_firewall_write",
                json!({
                    "host":"lab-1",
                    "op":"rule",
                    "acl":"McpAcl extra",
                    "verdict":"deny",
                    "protocol":"udp",
                    "source":"0.0.0.0",
                    "destination":"198.51.100.20",
                    "port":5_353_u16
                }),
                false,
            )
            .await?;
        assert_eq!(reply.error(), Some("validation_failed"));
        assert_eq!(
            sent(lab.router("lab-1")?, "access-list"),
            Vec::<String>::new()
        );
        lab.stop().await
    }
}
