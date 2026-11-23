//! Todo 16: the deepest new command fits the 1 MiB main stack Windows gives `kcc`.

use super::{
    lab::{CONFIRM, SshLab},
    spawning,
    support::{self, TestResult},
};

/// Todo 16: `kcc entware ssh bootstrap` runs to its end with a 1 MiB main stack; Linux
/// emulates Windows' limit with `ulimit -s`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_runs_within_a_one_mebibyte_main_stack() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);
    let (ticket, fingerprint) = lab.probe()?;
    let config = lab.base.env.path("kcc.toml");
    let file = lab.password_file.to_str().ok_or("non-UTF-8 path")?;
    let launcher = ["-c", "ulimit -s 1024 && exec \"$0\" \"$@\""];
    let kcc = [
        env!("CARGO_BIN_EXE_kcc"),
        "--config",
        config.to_str().ok_or("non-UTF-8 path")?,
        "--password-file",
        file,
    ];
    let step = [
        "entware",
        "ssh",
        "bootstrap",
        "--ticket",
        &ticket,
        "--fingerprint",
        &fingerprint,
    ];
    let args = [&launcher[..], &kcc, &CONFIRM, &step].concat();

    let run = support::finish(spawning::spawn(&mut lab.base.env.launch("sh", &args))?)?;

    lab.assert_clean(&run);
    assert_eq!(run.code, 0_i32, "{run:?}");
    lab.shutdown().await
}
