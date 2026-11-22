//! The `opkg` settings and reads of the Entware tools, and their result cap.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert results and the request log"
)]
mod tests {
    use serde_json::{Value, json};

    use crate::{
        helpers::{every, lab_on, lines},
        lab::{Lab, TestResult, admin},
    };

    /// The read tool.
    const READ: &str = "kcc_entware_read";
    /// The write tool.
    const WRITE: &str = "kcc_entware_write";

    /// The `value` of a successful `op` read of `lab-1`.
    async fn read(lab: &Lab, op: &str) -> TestResult<Value> {
        let reply = lab
            .call(READ, json!({"host": "lab-1", "op": op}), false)
            .await?;
        reply
            .value()?
            .get("value")
            .cloned()
            .ok_or_else(|| format!("{op}: no value").into())
    }

    /// The successful result of a write of `arguments`.
    async fn write(lab: &Lab, arguments: Value) -> TestResult<Value> {
        Ok(lab.call(WRITE, arguments, false).await?.value()?.clone())
    }

    /// Todo 14: enabling `opkg chroot` returns the `chroot_stops_ssh_management` warning,
    /// disabling it returns none, and the settings read follows.
    #[tokio::test]
    async fn enabling_chroot_returns_the_ssh_management_warning() -> TestResult {
        let lab = lab_on(every(false), admin()).await?;

        let on = write(
            &lab,
            json!({"host": "lab-1", "op": "chroot", "enabled": true}),
        )
        .await?;
        assert_eq!(on.get("applied"), Some(&json!(true)), "{on}");
        assert_eq!(on.get("unsaved"), Some(&json!(true)), "{on}");
        assert_eq!(
            on.get("warnings"),
            Some(&json!(["chroot_stops_ssh_management"])),
            "{on}"
        );
        assert_eq!(
            read(&lab, "settings").await?.get("chroot"),
            Some(&json!(true))
        );

        let off = write(
            &lab,
            json!({"host": "lab-1", "op": "chroot", "enabled": false}),
        )
        .await?;
        assert_eq!(off.get("warnings"), Some(&json!([])), "{off}");
        assert_eq!(
            read(&lab, "settings").await?.get("chroot"),
            Some(&json!(false))
        );
        lab.stop().await
    }

    /// Todo 14: the time zone, the init script and the removal reach the router as their
    /// `opkg` lines and stay unsaved.
    #[tokio::test]
    async fn settings_changes_apply_unsaved() -> TestResult {
        let lab = lab_on(every(true), admin()).await?;
        assert!(lab.router("lab-1")?.configure("opkg disk fixture-media:/"));

        for arguments in [
            json!({"host": "lab-1", "op": "timezone", "timezone": "Europe/Berlin"}),
            json!({"host": "lab-1", "op": "initrc", "initrc": "/opt/etc/init.d/rc.unslung", "confirm": true}),
            json!({"host": "lab-1", "op": "remove", "confirm": true}),
        ] {
            let result = write(&lab, arguments).await?;
            assert_eq!(result.get("unsaved"), Some(&json!(true)), "{result}");
        }

        let sent = lines(&lab)?;
        for line in [
            "opkg timezone Europe/Berlin",
            "opkg initrc /opt/etc/init.d/rc.unslung",
            "no opkg disk",
        ] {
            assert!(
                sent.iter().any(|sent_line| sent_line == line),
                "{line}: {sent:?}"
            );
        }
        assert_eq!(
            read(&lab, "settings").await?.get("disk"),
            Some(&Value::Null)
        );
        lab.stop().await
    }

    /// Todo 14: `status` reports the architecture and the eligible drive, `drives` the
    /// drives and the initializable media.
    #[tokio::test]
    async fn reads_return_the_status_and_the_drives() -> TestResult {
        let lab = lab_on(every(false), admin()).await?;

        let status = read(&lab, "status").await?;
        assert_eq!(status.get("arch"), Some(&json!("aarch64")), "{status}");
        assert_eq!(
            status.pointer("/drives/0/disk_arg"),
            Some(&json!("fixture-media:/")),
            "{status}"
        );
        let drives = read(&lab, "drives").await?;
        assert_eq!(drives.get("drives"), status.get("drives"), "{drives}");
        assert_eq!(
            drives.get("initializable"),
            Some(&json!(["Media0"])),
            "{drives}"
        );
        lab.stop().await
    }

    /// Todo 14: Entware results are cut to `max_result_bytes`, at the next call once the
    /// live gates lower it.
    #[tokio::test]
    async fn entware_results_stay_within_the_result_cap() -> TestResult {
        const CAP: u32 = 120;
        let lab = lab_on(every(false), admin()).await?;
        let whole = lab
            .call(READ, json!({"host": "lab-1", "op": "status"}), false)
            .await?
            .value()?
            .clone();
        assert!(whole.to_string().len() > usize::try_from(CAP)?, "{whole}");

        let mut capped = every(false);
        capped.max_result_bytes = CAP;
        lab.server.reconfigured(capped).publish_gates();

        for (tool, arguments) in [
            (READ, json!({"host": "lab-1", "op": "status"})),
            (
                WRITE,
                json!({"host": "lab-1", "op": "chroot", "enabled": true}),
            ),
        ] {
            let cut = lab.call(tool, arguments, false).await?.value()?.clone();
            assert!(
                cut.to_string().len() <= usize::try_from(CAP)?,
                "{tool}: {cut}"
            );
        }
        lab.stop().await
    }
}
