//! Cancelling an Entware SSH job: only a role with `Destructive` on the router may, and a
//! cancellation that arrives after the command was sent says that the command ran.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the job records"
)]
mod tests {
    use core::time::Duration;

    use kcc_app::permissions::{Permission, Role};
    use kcc_domain::entware::ssh::ops::job::Cancelled;
    use kcc_testkit::entware_ssh::Fault;
    use serde_json::json;
    use tokio::time::timeout;

    use crate::{
        rig::Rig,
        support::{Setup, TestResult, admin, every},
    };

    /// The session's role with `Read` and `Write` only.
    fn writer() -> Role {
        Role::new(
            "admin".to_owned(),
            [Permission::Read, Permission::Write],
            vec!["*".to_owned()],
        )
    }

    /// Starts an administrator's install of `htop` whose command the fake holds, and
    /// waits until it is held; returns the job id.
    async fn held_install(rig: &Rig) -> TestResult<String> {
        rig.ssh().set_fault(Some(Fault::HoldMutations));
        let id = rig.start_install("htop").await?;
        timeout(Duration::from_secs(30), rig.ssh().held(1)).await??;
        Ok(id)
    }

    /// Answers the held command.
    async fn release(rig: &Rig) {
        rig.ssh().set_fault(None);
        rig.ssh().release().await;
    }

    /// Todo 17: a role without `Destructive` cannot cancel a running Entware install:
    /// `forbidden`, and the job runs to `completed` with the package installed.
    #[tokio::test]
    async fn a_cancel_without_destructive_is_forbidden() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let id = held_install(&rig).await?;
        rig.roles().replace(vec![writer()]);
        let cancel = rig.call("kcc_job_cancel", json!({ "id": id })).await?;
        rig.roles().replace(vec![admin()]);
        release(&rig).await;
        assert_eq!(cancel.error(), Some("forbidden"), "{cancel:?}");
        let job = rig.ended(&id).await?;
        assert_eq!(
            (
                job.get("status"),
                job.get("message").filter(|message| !message.is_null())
            ),
            (Some(&json!("completed")), None),
            "{job}"
        );
        assert!(rig.ssh().installed().contains_key("htop"));
        rig.stop().await
    }

    /// Todo 17: a late cancellation says the command ran.
    ///
    /// Cancelled by an authorized role after the install command was sent, the job ends
    /// `cancelled` with a message that says the command ran, which the fake's state
    /// confirms: the package is installed.
    #[tokio::test]
    async fn a_cancel_after_the_command_was_sent_says_it_ran() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let id = held_install(&rig).await?;
        let cancel = rig.call("kcc_job_cancel", json!({ "id": id })).await?;
        release(&rig).await;
        assert_eq!(
            cancel.ok()?.get("cancelled"),
            Some(&json!(true)),
            "{cancel:?}"
        );
        let job = rig.ended(&id).await?;
        assert_eq!(
            (job.get("status"), job.get("message")),
            (
                Some(&json!("cancelled")),
                Some(&json!(Cancelled::AfterSend.to_string()))
            ),
            "{job}"
        );
        assert_eq!(
            rig.ssh().installed().get("htop").map(String::as_str),
            Some("3.3.0-1")
        );
        rig.stop().await
    }
}
