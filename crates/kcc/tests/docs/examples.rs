//! Shell examples tagged `kcc-doc-test` run against the fake router.
//!
//! Convention: blocks run in document order, one fresh environment per document, under
//! `bash -euo pipefail` in a temporary directory. The built `kcc` is first on `PATH`;
//! `HOME`, the XDG directories and the master key are private; `kcc.toml`, in the
//! directory the platform's `kcc` reads it from, admits the fake router's loopback address; `$ROUTER_URL` is the fake router and `router.pw`
//! holds its password. A non-zero exit fails the test.

use core::{error::Error, iter, net::SocketAddr, time::Duration};
use std::{
    env, fs,
    fs::File,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use kcc_app::secrets::MASTER_KEY_FILE_ENV;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use super::{
    markdown::{documents, fences},
    spawning,
};

/// The info-string word that marks an executable block.
const TAG: &str = "kcc-doc-test";

/// Longest time one block may run.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(120);

/// Whether a fence's info string marks an executable shell block.
fn tagged(info: &str) -> bool {
    let mut words = info.split_whitespace();
    words.next() == Some("bash") && words.any(|word| word == TAG)
}

/// The directory `kcc` reads its default `kcc.toml` from, on the platform `os` (a
/// [`env::consts::OS`] value), for a block whose `HOME` is `home` and whose
/// `XDG_CONFIG_HOME` is `home/config`.
///
/// Mirrors `kcc_app::settings::default_config_dir`, which reads the environment of the
/// process calling it and so cannot resolve the block's environment from here. This
/// module is unix-only, so the Windows `%APPDATA%` arm is not mirrored.
fn config_dir(os: &str, home: &Path) -> PathBuf {
    match os {
        "macos" => home.join("Library/Application Support/kcc"),
        _ => home.join("config/kcc"),
    }
}

/// A private home, config, state, master key and `kcc` on `PATH`.
struct Sandbox {
    /// Owner of every file; also the working directory of each block.
    directory: TempDir,
    /// The router address exported as `$ROUTER_URL`.
    router_url: String,
}

impl Sandbox {
    /// Prepares the files for a router reachable at `router_url`.
    fn new(router_url: String) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let root = directory.path();
        fs::create_dir_all(root.join("bin"))?;
        symlink(env!("CARGO_BIN_EXE_kcc"), root.join("bin/kcc"))?;
        let config = config_dir(env::consts::OS, &root.join("home"));
        fs::create_dir_all(&config)?;
        fs::write(
            config.join("kcc.toml"),
            "[outbound]\nallow_loopback = true\n",
        )?;
        let key = root.join("master.key");
        fs::write(&key, [23_u8; 32])?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        drop(kcc_testkit::write_secret_file(
            root,
            "router.pw",
            DEFAULT_PASSWORD,
        )?);
        Ok(Self {
            directory,
            router_url,
        })
    }

    /// Runs one block; the error carries the block, exit status and output.
    fn run(&self, block: &str) -> Result<(), Box<dyn Error>> {
        let root = self.directory.path();
        let path = env::join_paths(
            iter::once(root.join("bin"))
                .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
        )?;
        let home = root.join("home");
        let mut child = spawning::spawn(
            spawning::command("bash")
                .args(["--noprofile", "--norc", "-euo", "pipefail", "-c", block])
                .current_dir(root)
                .env_clear()
                .env("PATH", path)
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_STATE_HOME", home.join("state"))
                .env(MASTER_KEY_FILE_ENV, root.join("master.key"))
                .env("USER", "tester")
                .env("LANG", "C")
                .env("ROUTER_URL", &self.router_url)
                .stdin(Stdio::null())
                .stdout(File::create(root.join("stdout.log"))?)
                .stderr(File::create(root.join("stderr.log"))?),
        )?;
        let Some(status) = child.wait_timeout(BLOCK_TIMEOUT)? else {
            child.kill()?;
            let _: ExitStatus = child.wait()?;
            return Err(format!("timed out:\n{block}").into());
        };
        if status.success() {
            return Ok(());
        }
        let stdout = fs::read_to_string(root.join("stdout.log"))?;
        let stderr = fs::read_to_string(root.join("stderr.log"))?;
        Err(format!("{status} running:\n{block}\nstdout:\n{stdout}\nstderr:\n{stderr}").into())
    }
}

/// The URL of a fake router at `address`.
fn url(address: SocketAddr) -> String {
    format!("http://{address}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_tagged_example_runs_against_the_fake_router() -> Result<(), Box<dyn Error>> {
    let mut ran = 0_usize;
    for document in documents()? {
        let text = fs::read_to_string(&document)?;
        let blocks: Vec<_> = fences(&text)
            .into_iter()
            .filter(|fence| tagged(&fence.info))
            .collect();
        if blocks.is_empty() {
            continue;
        }
        let (address, handle) = FakeRouter::spawn().await?;
        let sandbox = Sandbox::new(url(address))?;
        for block in &blocks {
            sandbox
                .run(&block.body)
                .map_err(|error| format!("{}: {error}", document.display()))?;
            ran = ran.saturating_add(1);
        }
        handle.shutdown().await?;
    }
    assert!(ran >= 5, "only {ran} tagged blocks found");
    Ok(())
}

#[test]
fn the_config_lands_where_each_platform_reads_it() {
    let home = Path::new("/h");
    assert_eq!(
        config_dir("macos", home),
        Path::new("/h/Library/Application Support/kcc")
    );
    for os in ["linux", "freebsd"] {
        assert_eq!(config_dir(os, home), Path::new("/h/config/kcc"), "{os}");
    }
}

#[test]
fn a_failing_example_fails_the_runner() -> Result<(), Box<dyn Error>> {
    let sandbox = Sandbox::new(url(SocketAddr::from(([127, 0, 0, 1], 9))))?;
    sandbox.run("kcc --version\n")?;
    assert!(sandbox.run("kcc router test --router missing\n").is_err());
    Ok(())
}
