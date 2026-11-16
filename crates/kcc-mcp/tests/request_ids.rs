//! Every MCP call's log lines carry the request id its client gets. One test in its own
//! binary: a capturing subscriber set for one thread must not race other tests' spans.
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
    reason = "acceptance assertions establish the MCP logging contract"
)]
mod tests {
    use alloc::sync::Arc;
    use std::{
        io,
        sync::{Mutex, PoisonError},
    };

    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};
    use tracing::{Level, subscriber::set_default};

    use crate::lab::{Lab, TestResult, admin};

    /// Log output written by the subscriber under test.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        /// Everything logged so far.
        fn text(&self) -> String {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// E-09: the logged cause of a failed call carries the `request_id` its client got, for
    /// a fixed tool and a registry tool; a change's entry carries the id of its call.
    // NOT cancel-safe: the fixture owns tasks until explicit shutdown.
    #[tokio::test]
    async fn failure_causes_are_logged_with_the_clients_request_id() -> TestResult {
        let capture = Capture::default();
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let _default = set_default(subscriber);
        let router = FakeRouter::builder(Profile::default()).build()?;
        let lab = Lab::start(vec![("lab-1", router)], admin()).await?;
        for (tool, arguments, cause) in [
            (
                "kcc_job_cancel",
                json!({"id":"job-missing"}),
                "MCP job lookup failed",
            ),
            (
                "kcc_diagnostics_write",
                json!({"host":"lab-1","op":"ping","arguments":{"unknown-argument":true}}),
                "MCP diagnostic validation failed",
            ),
        ] {
            let reply = lab.call(tool, arguments, false).await?;

            let id = reply
                .failure()
                .and_then(|failure| failure.get("request_id"))
                .and_then(Value::as_str)
                .ok_or("no request id")?;
            let logged = capture.text();
            let line = logged
                .lines()
                .find(|line| line.contains(cause))
                .ok_or_else(|| format!("{tool}: cause not logged: {logged}"))?;
            assert!(line.contains(id), "{tool}: {id} missing in {line}");
        }
        let change = json!({
            "host": "lab-1", "catalog_path": "ip host", "path": ["ip", "host"],
            "value": {"domain": "traced.example", "address": "192.0.2.12"},
        });
        let applied = lab.call("kcc_rci_execute", change, false).await?;
        assert_eq!(applied.error(), None, "{applied:?}");
        let entry = lab
            .audit()?
            .into_iter()
            .find(|entry| entry.action == "router.change")
            .ok_or("change not audited")?;
        assert!(entry.request_id.starts_with("mcp-"), "{}", entry.request_id);
        lab.stop().await
    }
}
