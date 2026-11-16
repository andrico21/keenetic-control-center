//! MCP smoke over an in-process session: read tools plus one reversible write.
//!
//! The live test is `#[ignore]`d; run it with
//! `cargo test -p kcc-mcp --test live_mcp -- --ignored`. It needs `KCC_LIVE_URL`,
//! `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE` and `KCC_LIVE_ALLOW_SERIAL`; the write segment
//! also needs `KCC_LIVE_ALLOW_WRITE=1` and `KCC_LIVE_TARGET_CONFIG` whose `[[routers]]` entry
//! for `KCC_LIVE_URL` has `test_device = true`. A missing variable logs `live-skip:<reason>`.
//! The hermetic twin drives the same function against the 5.1 KN-1811 fake router.
extern crate alloc;

#[path = "live_mcp/session.rs"]
mod session;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "smoke assertions establish the MCP contract against a router"
)]
mod tests {
    use core::error::Error;
    use std::{env, fs, path::PathBuf};

    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        live_matrix::{self, Outcome, Suite},
        model::{Firmware, Model, Profile},
    };
    use secrecy::{SecretString, zeroize::Zeroizing};
    use tempfile::TempDir;

    use super::session::{Smoke, Target, TestResult, read_serial, smoke};

    /// `.omo/evidence/task-51-keenetic-control-center.json` in the workspace.
    fn matrix_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.omo/evidence/task-51-keenetic-control-center.json")
    }

    /// Reads one non-empty variable or names it.
    fn read(name: &'static str, reason: &'static str) -> Result<String, &'static str> {
        env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or(reason)
    }

    /// The live contract, or the first missing variable.
    fn live_env() -> Result<Result<Target, Box<dyn Error>>, &'static str> {
        let url = read("KCC_LIVE_URL", "kcc_live_url-unset")?;
        let login = read("KCC_LIVE_LOGIN", "kcc_live_login-unset")?;
        let password_file = read("KCC_LIVE_PASSWORD_FILE", "kcc_live_password_file-unset")?;
        let allowed = read("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
            .split(',')
            .map(|serial| serial.trim().to_owned())
            .filter(|serial| !serial.is_empty())
            .collect();
        let write = read("KCC_LIVE_ALLOW_WRITE", "").as_deref() == Ok("1");
        let config = read("KCC_LIVE_TARGET_CONFIG", "").ok().map(PathBuf::from);
        Ok(fs::read_to_string(&password_file)
            .map(|text| {
                let raw = Zeroizing::new(text);
                Target {
                    url,
                    login,
                    password: SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned()),
                    password_file: PathBuf::from(&password_file),
                    allowed,
                    write_config: config.filter(|_config| write),
                    allow_loopback: false,
                }
            })
            .map_err(Into::into))
    }

    #[tokio::test]
    #[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
    async fn live_mcp_smoke() -> TestResult {
        let target = match live_env() {
            Ok(target) => target?,
            Err(reason) => {
                tracing::warn!("live-skip:{reason}");
                return Ok(live_matrix::record_skip(
                    &matrix_path(),
                    "live_mcp",
                    reason,
                )?);
            }
        };
        let Smoke { run, wrote } = smoke(target).await?;
        let reason = if wrote {
            "reads and write"
        } else {
            "reads only"
        };
        let suite = Suite::new("live_mcp", Outcome::Pass, reason);
        Ok(live_matrix::record(&matrix_path(), &run, suite)?)
    }

    /// The twin: every read tool answers and the client write is applied, read back and
    /// reverted, leaving the running configuration byte-identical.
    #[tokio::test]
    async fn mcp_smoke_runs_against_the_fake_router() -> TestResult {
        let files = TempDir::new()?;
        let (address, handle) = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_1)?)
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let url = format!("http://{address}");
        let password_file =
            kcc_testkit::write_secret_file(files.path(), "password", DEFAULT_PASSWORD)?;
        let config = files.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[outbound]\nallow_loopback = true\n\n[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\ntest_device = true\n",
                password_file.display().to_string()
            ),
        )?;
        let running = handle.running_config_text();
        let mut target = Target {
            url,
            login: DEFAULT_LOGIN.to_owned(),
            password: SecretString::from(DEFAULT_PASSWORD.to_owned()),
            password_file,
            allowed: Vec::new(),
            write_config: Some(config),
            allow_loopback: true,
        };
        target.allowed = vec![read_serial(&target).await?];
        let Smoke { run: _, wrote } = smoke(target).await?;
        assert!(wrote, "the write segment did not run");
        assert_eq!(handle.running_config_text(), running, "router changed");
        let commands = handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                "system configuration fail-safe timer reboot 900",
                "known host \"kcc-live-51\" 02:00:00:00:51:02",
                "no known host 02:00:00:00:51:02",
                "no system configuration fail-safe timer",
            ],
            "unexpected router writes"
        );
        handle.shutdown().await?;
        Ok(())
    }
}
