//! A change the router applied while another process holds the audit append lock.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the MCP tool contract"
)]
mod tests {
    use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};

    use crate::lab::{Lab, TestResult, admin};

    /// An ordinary `ip host` write of `domain`.
    fn host(domain: &str) -> Value {
        json!({
            "host": "lab-1",
            "catalog_path": "ip host",
            "path": ["ip", "host"],
            "value": {"domain": domain, "address": "192.0.2.12"},
        })
    }

    /// An ordinary write under a held lock is a success marked `audit_pending`, never a
    /// failure; once the lock is free its entry is written before a later change's.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test(start_paused = true)]
    async fn an_applied_write_under_a_held_lock_succeeds_with_its_entry_pending() -> TestResult {
        let lab = Lab::start(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
        )
        .await?;
        let lock = StateStore::open(&lab.state_dir())?.try_lock(AUDIT_FILE_NAME)?;

        let reply = lab
            .call("kcc_rci_execute", host("held.example"), false)
            .await?;

        assert_eq!(reply.error(), None, "{reply:?}");
        let value = reply.value()?;
        assert_eq!(value.get("unsaved"), Some(&json!(true)), "{value}");
        assert_eq!(value.get("audit_pending"), Some(&json!(true)), "{value}");
        drop(lock);
        let later = lab
            .call("kcc_rci_execute", host("free.example"), false)
            .await?;
        assert_eq!(later.value()?.get("audit_pending"), None, "{later:?}");
        let changes: Vec<Value> = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "router.change")
            .map(|entry| entry.params_redacted)
            .collect();
        assert_eq!(changes.len(), 2, "both entries are written: {changes:?}");
        lab.stop().await
    }
}
