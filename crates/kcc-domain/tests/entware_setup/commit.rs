//! The components step: a rebooting component commit inside the setup job, then a fresh
//! change set.

use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::JobStatus,
};
use kcc_domain::{
    configuration,
    entware::{self, setup::SetupFailure},
};
use kcc_testkit::model::{Model, Profile};

use super::{AARCH64_URL, DRIVE, Lab, kn1811_with, on_drive, on_profile, step};
use crate::support::{PROFILES, TestResult, administrator};

/// The progress a component commit reports once the router went down.
const DOWN: u8 = 60;

/// The `components ...` lines of `lines`.
fn component_lines(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.starts_with("components "))
        .collect()
}

/// Todo 10: a KN-1811 without `opkg` and `ext` gets both, then Entware.
///
/// The job installs both components by a rebooting component commit, continues after the
/// restart with a fresh change set, installs Entware, reads `opkg disk` back and ends
/// unsaved without saving.
#[tokio::test(start_paused = true)]
async fn kn1811_setup_commits_the_components_then_installs_entware() -> TestResult {
    for firmware in PROFILES {
        let mut lab = Lab::spawn(on_profile(Profile::new(Model::Kn1811, firmware)?)).await?;
        let mark = lab.handle().request_log().len();

        let id = lab.start(on_drive()).await?;
        let record = lab.finished(&id).await?;

        assert_eq!(
            record.status,
            JobStatus::Completed,
            "{firmware}: {:?}",
            record.message
        );
        let lines = lab.lines_since(mark);
        assert_eq!(
            lines,
            [
                "components install opkg".to_owned(),
                "components install ext".to_owned(),
                "components commit".to_owned(),
                format!("opkg disk {DRIVE} {AARCH64_URL}"),
            ],
            "{firmware}"
        );
        let after = lab.fixture.registry().poll_info("router").await?;
        assert!(after.components.contains("opkg") && after.components.contains("ext"));
        let settings = entware::read_settings(lab.fixture.context()).await?;
        assert_eq!(settings.disk.as_deref(), Some(DRIVE), "{firmware}");
        let last = configuration::read_last_change(lab.fixture.context()).await?;
        assert_eq!(last.unsaved, Some(true), "{firmware}");
        let progress = lab.progress(&id);
        assert_eq!(progress.last().and_then(step), Some("done"), "{firmware}");
    }
    Ok(())
}

/// Todo 10: only the component that is not installed is queued.
#[tokio::test(start_paused = true)]
async fn only_the_missing_component_is_queued() -> TestResult {
    let lab = Lab::spawn(kn1811_with("base,usb,storage,opkg")).await?;
    let mark = lab.handle().request_log().len();

    let id = lab.start(on_drive()).await?;
    let record = lab.finished(&id).await?;

    assert_eq!(record.status, JobStatus::Completed, "{:?}", record.message);
    assert_eq!(
        component_lines(&lab.lines_since(mark)),
        ["components install ext", "components commit"]
    );
    Ok(())
}

/// Todo 10: when another writer takes the router's lease during the restart, the job ends
/// with "components installed; run setup again" and sends no `opkg disk`.
#[tokio::test(start_paused = true)]
async fn a_lease_taken_during_the_restart_ends_with_run_setup_again() -> TestResult {
    let mut lab = Lab::spawn(on_profile(Profile::latest(Model::Kn1811))).await?;
    let (_state, elsewhere) = lab.fixture.separate_workflow().await?;
    let role = administrator();
    let other = Actor::new(ActorKind::Cli, "other".to_owned());
    let changes = elsewhere
        .begin("router", other.clone(), &role, false)
        .await?;
    let mark = lab.handle().request_log().len();
    let id = lab.start_with(&role, changes, on_drive()).await?;
    lab.reached(&id, |event| event.progress == DOWN).await?;

    let held = lab.fixture.workflow().reserve("router", &other, &role)?;
    let record = lab.finished(&id).await?;
    drop(held);

    assert_eq!(record.status, JobStatus::Failed);
    assert_eq!(
        record.message,
        Some(SetupFailure::ComponentsInstalled.to_string())
    );
    let lines = lab.lines_since(mark);
    assert_eq!(
        component_lines(&lines),
        [
            "components install opkg",
            "components install ext",
            "components commit"
        ]
    );
    assert!(!lines.iter().any(|line| line.starts_with("opkg disk")));
    let after = lab.fixture.registry().poll_info("router").await?;
    assert!(after.components.contains("opkg") && after.components.contains("ext"));
    Ok(())
}
