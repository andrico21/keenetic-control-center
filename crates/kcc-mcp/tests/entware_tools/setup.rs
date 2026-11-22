//! The Entware setup job over MCP, under a paused tokio clock: the installer's log polls
//! take no real time.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the job and the request log"
)]
mod tests {
    use core::time::Duration;

    use kcc_app::jobs::JobStatus;
    use kcc_testkit::{
        FakeRouter,
        model::{Firmware, Model, Profile},
    };
    use serde_json::{Value, json};
    use tokio::time::timeout;

    use crate::{
        helpers::{every, lab_with, lines},
        lab::{Lab, TestResult, admin},
    };

    /// The write tool.
    const WRITE: &str = "kcc_entware_write";
    /// The aarch64 installer of the closed table.
    const AARCH64_URL: &str =
        "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz";
    /// The little-endian MIPS installer of the closed table.
    const MIPSEL_URL: &str =
        "https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz";
    /// Past every limit of the setup job, in tokio time.
    const JOB_LIMIT: Duration = Duration::from_hours(2);

    /// A 5.1 `model` reporting `arch` with `opkg` and `ext` installed.
    fn ready(model: Model, identity: (&str, &str)) -> TestResult<FakeRouter> {
        let (hw_id, arch) = identity;
        let version = json!({
            "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
            "model": "Keenetic", "device": "Keenetic", "hw_id": hw_id,
            "hw_version": "10000000", "hw_type": "router", "sandbox": "stable",
            "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.", "series": "KN",
            "region": "EA", "arch": arch,
            "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
            "ndw": {"components": "base,usb,storage,opkg,ext", "features": "wifi2ghz"}
        });
        Ok(FakeRouter::builder(Profile::latest(model))
            .show_fixture("version", version)
            .build()?)
    }

    /// Starts the setup of `arguments` and waits for its job; returns the job's status.
    async fn finished(lab: &Lab, arguments: Value) -> TestResult<JobStatus> {
        let reply = lab.call(WRITE, arguments, false).await?;
        let job = reply
            .value()?
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or("no job id")?;
        timeout(JOB_LIMIT, lab.jobs.ended(job)).await?;
        let record = lab.jobs.get(job)?;
        assert_eq!(record.kind, "entware.setup");
        Ok(record.status)
    }

    /// Todo 14: `setup` starts the setup job, which installs with the installer the
    /// router's `aarch64` architecture selects and ends completed.
    #[tokio::test(start_paused = true)]
    async fn setup_runs_as_a_job_with_the_automatic_installer() -> TestResult {
        let router = ready(Model::Kn1811, ("KN-1811", "aarch64"))?;
        let lab = lab_with(router, every(true), admin()).await?;

        let status = finished(
            &lab,
            json!({"host": "lab-1", "op": "setup", "drive": "fixture-media:/", "confirm": true}),
        )
        .await?;

        assert_eq!(status, JobStatus::Completed);
        let installs = lines(&lab)?
            .into_iter()
            .filter(|line| line.starts_with("opkg disk "))
            .collect::<Vec<_>>();
        assert_eq!(
            installs,
            [format!("opkg disk fixture-media:/ {AARCH64_URL}")]
        );
        lab.stop().await
    }

    /// Todo 14: on a router reporting `mips` the setup without `arch` is refused with
    /// `invalid_arguments` and nothing is installed; with `arch: mipsel` it installs that
    /// installer.
    #[tokio::test(start_paused = true)]
    async fn an_ambiguous_mips_router_needs_the_arch() -> TestResult {
        let router = ready(Model::Kn1010, ("KN-1010", "mips"))?;
        let lab = lab_with(router, every(true), admin()).await?;
        let setup = json!({"host": "lab-1", "op": "setup", "drive": "internal", "confirm": true});

        let refused = lab.call(WRITE, setup.clone(), false).await?;
        assert_eq!(refused.error(), Some("invalid_arguments"), "{refused:?}");
        assert!(
            lines(&lab)?
                .iter()
                .all(|line| !line.starts_with("opkg disk")),
            "an install was sent"
        );

        let mut chosen = setup;
        if let Some(object) = chosen.as_object_mut() {
            drop(object.insert("arch".to_owned(), json!("mipsel")));
        }
        assert_eq!(finished(&lab, chosen).await?, JobStatus::Completed);
        let installs = lines(&lab)?
            .into_iter()
            .filter(|line| line.starts_with("opkg disk "))
            .collect::<Vec<_>>();
        assert_eq!(installs, [format!("opkg disk storage:/ {MIPSEL_URL}")]);
        lab.stop().await
    }
}
