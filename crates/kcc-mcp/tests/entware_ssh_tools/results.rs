//! What the tools answer.
//!
//! Mutations run as jobs and are read back through the listings, reads answer parsed
//! values only with every string cleaned of control characters, and a read behind a
//! mutation that holds the router's session is bounded.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the results"
)]
mod tests {
    use alloc::collections::BTreeSet;
    use core::time::Duration;

    use kcc_testkit::{
        entware_install::record,
        entware_ssh::{DEFAULT_PASSWORD, Fault},
    };
    use serde_json::{Value, json};
    use tokio::time::timeout;

    use crate::{
        rig::Rig,
        support::{PACKAGES, SERVICES, Setup, TestResult, admin, every},
    };

    /// Text of the fake's raw output and of the enrolment that must never reach a result.
    const RAW: [&str; 15] = [
        "Installing",
        "Configuring",
        "Downloading",
        "Updated list",
        "Checking",
        "Starting",
        "alive.",
        "dead.",
        "Collected errors",
        " - ",
        "/opt/",
        "kcc:lab-1",
        "ssh-ed25519",
        "OPENSSH",
        DEFAULT_PASSWORD,
    ];

    /// `arguments` for `lab-1`, confirmed.
    fn call(arguments: Value) -> Value {
        let mut full = json!({"host": "lab-1", "confirm": true});
        if let (Value::Object(target), Value::Object(source)) = (&mut full, arguments) {
            target.extend(source);
        }
        full
    }

    /// Every string of `value`, keys included.
    fn strings(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::String(text) => found.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
            Value::Object(members) => {
                for (key, member) in members {
                    found.push(key.clone());
                    strings(member, found);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Fails when a string of `value` has a control character or raw-output text.
    fn clean(value: &Value) -> TestResult {
        let mut found = Vec::new();
        strings(value, &mut found);
        for text in found {
            if text.chars().any(char::is_control) || RAW.iter().any(|raw| text.contains(raw)) {
                return Err(format!("raw text {text:?} in {value}").into());
            }
        }
        Ok(())
    }

    /// The `name` members of the items of `member` in `value`.
    fn names(value: &Value, member: &str) -> TestResult<BTreeSet<String>> {
        Ok(value
            .get(member)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("no {member}: {value}"))?
            .iter()
            .filter_map(|item| item.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect())
    }

    /// Todo 17: `install` starts a write job (`entware.ssh.install`) and answers its id;
    /// the job completes and the package listing reads the installed version back.
    #[tokio::test]
    async fn install_runs_as_a_job_and_reads_back() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let started = rig
            .call(PACKAGES, call(json!({"op": "install", "package": "htop"})))
            .await?;
        clean(started.ok()?)?;
        let job = rig.finished(&started).await?;
        assert_eq!(
            (job.get("kind"), job.get("status"), job.get("router")),
            (
                Some(&json!("entware.ssh.install")),
                Some(&json!("completed")),
                Some(&json!("lab-1"))
            ),
            "{job}"
        );
        let listed = rig.call(PACKAGES, call(json!({"op": "list"}))).await?;
        let packages = listed.ok()?.get("packages").ok_or("no packages")?;
        assert!(
            packages
                .as_array()
                .is_some_and(|items| items.contains(&json!({"name": "htop", "version": "3.3.0-1"}))),
            "{listed:?}"
        );
        assert_eq!(
            rig.ssh().installed().get("htop").map(String::as_str),
            Some("3.3.0-1")
        );
        rig.stop().await
    }

    /// Todo 17: a service start runs as a job; `status` then reads it running.
    #[tokio::test]
    async fn a_service_start_runs_as_a_job_and_reads_back() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let before = rig
            .call(
                SERVICES,
                call(json!({"op": "status", "service": "S50nginx"})),
            )
            .await?;
        assert_eq!(
            before.ok()?,
            &json!({"op": "status", "service": "S50nginx", "state": "stopped"})
        );
        let started = rig
            .call(
                SERVICES,
                call(json!({"op": "start", "service": "S50nginx"})),
            )
            .await?;
        let job = rig.finished(&started).await?;
        assert_eq!(job.get("kind"), Some(&json!("entware.ssh.service_start")));
        assert_eq!(job.get("status"), Some(&json!("completed")), "{job}");
        let after = rig
            .call(
                SERVICES,
                call(json!({"op": "status", "service": "S50nginx"})),
            )
            .await?;
        assert_eq!(after.ok()?.get("state"), Some(&json!("running")));
        rig.stop().await
    }

    /// Todo 17: every read answers parsed names, versions and states only.
    ///
    /// The escape sequence and bell in a version and in a log message are removed, and no
    /// raw output, key or password reaches any result, job status included.
    #[tokio::test]
    async fn results_are_parsed_values_without_control_characters() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        rig.router().insert_log(
            10,
            record("I", "dropbear[123]: hello\u{1b}[31m red\u{7} world"),
        );
        let list = rig.call(PACKAGES, call(json!({"op": "list"}))).await?;
        assert_eq!(
            list.ok()?,
            &json!({"op": "list", "packages": [
                {"name": "evil", "version": "1.0-1"},
                {"name": "nano", "version": "7.2-1"}
            ]})
        );
        let upgradable = rig
            .call(PACKAGES, call(json!({"op": "upgradable"})))
            .await?;
        assert_eq!(
            upgradable.ok()?,
            &json!({"op": "upgradable", "packages": [
                {"name": "nano", "version": "7.2-1", "new_version": "7.4-1"}
            ]})
        );
        let services = rig.call(SERVICES, call(json!({"op": "list"}))).await?;
        assert_eq!(
            names(services.ok()?, "services")?,
            BTreeSet::from(["S50nginx".to_owned(), "S51dropbear".to_owned()])
        );
        let log = rig
            .call(
                SERVICES,
                call(json!({"op": "log", "service": "S51dropbear"})),
            )
            .await?;
        let messages = log
            .ok()?
            .get("records")
            .and_then(Value::as_array)
            .ok_or("no records")?
            .iter()
            .filter_map(|item| item.get("message").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(messages, ["hello red world"], "{log:?}");
        let update = rig.call(PACKAGES, call(json!({"op": "update"}))).await?;
        let job = rig.finished(&update).await?;
        for value in [
            list.ok()?,
            upgradable.ok()?,
            services.ok()?,
            log.ok()?,
            update.ok()?,
            &job,
        ] {
            clean(value)?;
        }
        rig.stop().await
    }

    /// Todo 17: a read behind a mutation that holds the router's SSH session ends at the
    /// read bound with `conflict` instead of waiting; the mutation completes afterwards.
    #[tokio::test]
    async fn a_read_behind_a_held_mutation_is_bounded() -> TestResult {
        let setup = Setup::new(every(), admin()).limit(Duration::from_millis(500));
        let rig = Rig::start(setup).await?;
        rig.ssh().set_fault(Some(Fault::HoldMutations));
        let install = rig.call(PACKAGES, call(json!({"op": "install", "package": "htop"})));
        let behind = async {
            timeout(Duration::from_secs(30), rig.ssh().held(1)).await??;
            let list = rig.call(PACKAGES, call(json!({"op": "list"})));
            let read = timeout(Duration::from_secs(30), list).await;
            rig.ssh().set_fault(None);
            rig.ssh().release().await;
            read?
        };
        let (installing, behind_it) = tokio::join!(install, behind);
        let (started, read) = (installing?, behind_it?);
        assert_eq!(read.error(), Some("conflict"), "{read:?}");
        let job = rig.finished(&started).await?;
        assert_eq!(job.get("status"), Some(&json!("completed")), "{job}");
        rig.stop().await
    }
}
