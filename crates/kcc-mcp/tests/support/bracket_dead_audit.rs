//! A dead audit writer over MCP: one that dies on the bracket's first receipt still lets the
//! bracket disarm, and one already dead refuses the next change before any router request.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert wire and request-log contracts"
)]
mod tests {
    use std::{fs::OpenOptions, io::Write as _};

    use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
    use kcc_testkit::{FaultInjection, bracket::Recovery};
    use serde_json::{Value, json};

    use crate::{
        bracket::{commands, router},
        lab::{Lab, TestResult, admin},
    };

    /// A confirmed raw management change.
    fn change() -> Value {
        json!({"host":"lab-1","line":"ip http port 8082","confirm":true})
    }

    /// Starts a lab whose audit writer dies on its next append: that append finds a last
    /// line that is not an audit entry.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    async fn doomed() -> TestResult<Lab> {
        let fake = router("router", FaultInjection::default())?;
        let lab = Lab::start(vec![("lab-1", fake)], admin()).await?;
        let _lock = StateStore::open(&lab.state_dir())?.lock(AUDIT_FILE_NAME)?;
        OpenOptions::new()
            .append(true)
            .open(lab.state_dir().join(AUDIT_FILE_NAME))?
            .write_all(b"not an entry\n")?;
        Ok(lab)
    }

    /// The arm's receipt kills the writer: the change fails, the disarm still goes out and
    /// the timer is off.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn a_writer_dying_after_the_arm_still_disarms() -> TestResult {
        let lab = doomed().await?;

        let reply = lab.call("kcc_cli_parse", change(), false).await?;

        assert_eq!(reply.error(), Some("internal"), "{reply:?}");
        let sent = commands(&lab)?;
        let [arm, disarm] = Recovery::FailSafeTimer.lines();
        assert_eq!(sent.first().map(String::as_str), Some(arm), "{sent:?}");
        assert_eq!(sent.last().map(String::as_str), Some(disarm), "{sent:?}");
        assert!(!lab.router("lab-1")?.recovery_armed(), "the timer is off");
        lab.stop().await
    }

    /// Once the writer is dead, a change is refused before kcc sends anything.
    // NOT cancel-safe: the fixture owns router and MCP tasks.
    #[tokio::test]
    async fn a_dead_writer_refuses_the_change_before_any_router_request() -> TestResult {
        let lab = doomed().await?;
        let unconfirmed = json!({"host":"lab-1","line":"ip http port 8082"});
        let refused = lab.call("kcc_cli_parse", unconfirmed, false).await?;
        assert_eq!(refused.error(), Some("confirm_required"), "{refused:?}");
        let before = lab.requests("lab-1")?;

        let reply = lab.call("kcc_cli_parse", change(), false).await?;

        assert_eq!(reply.error(), Some("internal"), "{reply:?}");
        assert_eq!(lab.requests("lab-1")?, before, "no router request");
        lab.stop().await
    }
}
