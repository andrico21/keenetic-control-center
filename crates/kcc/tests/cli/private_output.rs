//! Migration output files never write through planted symlinks.

use std::{fs, os::unix::fs::symlink, path::Path};

use kcc_testkit::model::Firmware;
use tempfile::TempDir;

use super::{migrate::target, support::TestResult};

/// A file outside the output directory that a planted symlink names.
struct Victim {
    /// Directory holding only the victim file.
    directory: TempDir,
}

impl Victim {
    /// Creates the outside file with known content.
    fn new() -> TestResult<Self> {
        let directory = TempDir::new()?;
        fs::write(directory.path().join("victim"), "victim")?;
        Ok(Self { directory })
    }

    /// Plants a symlink at `link` naming the victim.
    fn plant(&self, link: &Path) -> TestResult {
        symlink(self.directory.path().join("victim"), link)?;
        Ok(())
    }

    /// Asserts the victim is unchanged and nothing new appeared beside it.
    fn assert_untouched(&self) -> TestResult {
        assert_eq!(
            fs::read_to_string(self.directory.path().join("victim"))?,
            "victim",
            "the linked file is not written"
        );
        assert_eq!(
            fs::read_dir(self.directory.path())?.count(),
            1,
            "nothing new appears beside the linked file"
        );
        Ok(())
    }
}

/// F-22, SEC2-17: `migrate plan --out` and `migrate report --out` ignore a
/// symlink at the old predictable temporary name and refuse a symlink at the
/// output path; the file a link names is never written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_and_report_outputs_never_write_through_symlinks() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    let victim = Victim::new()?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan = env.path("plan.json");
    let report = env.path("report.md");
    let linked = env.path("linked.json");
    victim.plant(&env.path("plan.kcc-tmp"))?;
    victim.plant(&env.path("report.kcc-tmp"))?;
    victim.plant(&linked)?;
    let arg = |path: &Path| path.display().to_string();

    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", &arg(&plan)])?;
    let reported = env.kcc(&[
        "migrate",
        "report",
        "--from",
        &source,
        "--out",
        &arg(&report),
    ])?;
    let refused = env.kcc(&["migrate", "plan", "--from", &source, "--out", &arg(&linked)])?;

    assert_eq!(planned.code, 0_i32, "{planned:?}");
    assert_eq!(reported.code, 0_i32, "{reported:?}");
    assert_eq!(refused.code, 1_i32, "{refused:?}");
    victim.assert_untouched()?;
    for written in [&plan, &report] {
        assert!(
            fs::symlink_metadata(written)?.is_file(),
            "{}",
            written.display()
        );
    }
    assert!(fs::symlink_metadata(&linked)?.file_type().is_symlink());
    handle.shutdown().await?;
    Ok(())
}

/// F-22, SEC2-17: `migrate apply --report` ignores a symlink at the old
/// predictable temporary name; the report is a new file in its directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_report_never_writes_through_a_symlink() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;
    let victim = Victim::new()?;
    let source = format!("file:{}", env.path("source.txt").display());
    let plan = env.path("plan.json").display().to_string();
    let report = env.path("apply.json");
    victim.plant(&env.path("apply.kcc-tmp"))?;
    let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", &plan])?;
    assert_eq!(planned.code, 0_i32, "{planned:?}");

    let applied = env.kcc(&[
        "migrate",
        "apply",
        "--from",
        &source,
        "--plan",
        &plan,
        "--yes",
        "--finish",
        "commit",
        "--report",
        &report.display().to_string(),
    ])?;

    assert_eq!(applied.code, 0_i32, "{applied:?}");
    victim.assert_untouched()?;
    assert!(fs::symlink_metadata(&report)?.is_file());
    handle.shutdown().await?;
    Ok(())
}
