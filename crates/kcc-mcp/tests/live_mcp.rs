//! MCP smoke over an in-process session: read tools plus one reversible write.
//!
//! The live test is `#[ignore]`d; run it with
//! `cargo test -p kcc-mcp --test live_mcp -- --ignored`. It needs `KCC_LIVE_URL`,
//! `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE`, `KCC_LIVE_ALLOW_SERIAL` and
//! `KCC_LIVE_TARGET_CONFIG` whose `[[routers]]` entry for `KCC_LIVE_URL` has
//! `test_device = true`; the write segment also needs `KCC_LIVE_ALLOW_WRITE=1`. A missing
//! variable logs `live-skip:<reason>`; the MCP registry follows the configuration's
//! `[outbound]` policy.
//! The hermetic twin drives the same function against the 5.1 KN-1811 fake router.
extern crate alloc;

#[path = "../../kcc/tests/support/live_gate.rs"]
mod live_gate;
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
    use std::{env, fs, io, path::PathBuf};

    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
        live_matrix::{self, Outcome, Suite},
        model::{Firmware, Model, Profile},
    };
    use secrecy::{SecretString, zeroize::Zeroizing};
    use tempfile::TempDir;

    use super::{
        live_gate::Refusal,
        session::{Smoke, Target, TestResult, read_serial, smoke},
    };

    /// An `[outbound]` table admitting the fake on loopback.
    ///
    /// The documentation network keeps the copied `allowed_networks` non-empty.
    const LOOPBACK: &str =
        "[outbound]\nallow_loopback = true\nallowed_networks = [\"198.51.100.0/24\"]\n\n";

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
        let config = read("KCC_LIVE_TARGET_CONFIG", "kcc_live_target_config-unset")?;
        let write = read("KCC_LIVE_ALLOW_WRITE", "").as_deref() == Ok("1");
        if !write {
            tracing::warn!("live-skip:kcc_live_allow_write-not-1 (writes skipped)");
        }
        Ok(fs::read_to_string(&password_file)
            .map(|text| {
                let raw = Zeroizing::new(text);
                Target {
                    url,
                    login,
                    password: SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned()),
                    password_file: PathBuf::from(&password_file),
                    allowed,
                    config: PathBuf::from(config),
                    write,
                    allow_loopback: false,
                }
            })
            .map_err(Into::into))
    }

    #[tokio::test]
    #[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
    async fn live_mcp_smoke() -> TestResult {
        drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
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

    /// A 5.1 KN-1811 fake with a configuration whose `[outbound]` table is `outbound`.
    struct Lab {
        /// Temporary files.
        _files: TempDir,
        /// Router handle.
        handle: Handle,
        /// The smoke's inputs, writes requested.
        target: Target,
    }

    /// Starts the fake and writes its profile with `test_device`.
    // NOT cancel-safe: starts a background router and writes temporary files.
    async fn lab(outbound: &str, test_device: bool) -> Result<Lab, Box<dyn Error>> {
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
                "{outbound}[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\ntest_device = {test_device}\n",
                password_file.display().to_string()
            ),
        )?;
        let target = Target {
            url,
            login: DEFAULT_LOGIN.to_owned(),
            password: SecretString::from(DEFAULT_PASSWORD.to_owned()),
            password_file,
            allowed: Vec::new(),
            config,
            write: true,
            allow_loopback: true,
        };
        Ok(Lab {
            _files: files,
            handle,
            target,
        })
    }

    /// Parser lines the router received.
    fn commands(handle: &Handle) -> Vec<String> {
        handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(ToOwned::to_owned))
            .collect()
    }

    /// The twin: every read tool answers and the client write is applied, read back and
    /// reverted, leaving the running configuration byte-identical.
    #[tokio::test]
    async fn mcp_smoke_runs_against_the_fake_router() -> TestResult {
        let Lab {
            _files,
            handle,
            mut target,
        } = lab(LOOPBACK, true).await?;
        let running = handle.running_config_text();
        target.allowed = vec![read_serial(&target).await?];
        let Smoke { run: _, wrote } = smoke(target).await?;
        assert!(wrote, "the write segment did not run");
        assert_eq!(handle.running_config_text(), running, "router changed");
        assert_eq!(
            commands(&handle),
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

    /// T-08: the read-only smoke refuses a profile without `test_device = true`.
    ///
    /// The refusal comes before the router receives a single request.
    #[tokio::test]
    async fn read_only_smoke_refuses_a_profile_without_test_device_before_contact() -> TestResult {
        let Lab {
            _files,
            handle,
            mut target,
        } = lab(LOOPBACK, false).await?;
        target.write = false;
        target.allowed = vec!["S0000000000001".to_owned()];
        let refusal = smoke(target)
            .await
            .err()
            .and_then(|error| error.downcast_ref::<Refusal>().copied());
        assert_eq!(refusal, Some(Refusal::NotTestDevice));
        assert_eq!(handle.request_count(), 0, "the gate contacted the router");
        handle.shutdown().await?;
        Ok(())
    }

    /// T-02: the MCP registry follows the admitted `[outbound]` policy, not a test flag.
    ///
    /// A configuration that refuses the router's address fails the smoke, and the router
    /// receives no parser line.
    #[tokio::test]
    async fn smoke_follows_the_admitted_outbound_policy() -> TestResult {
        let Lab {
            _files,
            handle,
            mut target,
        } = lab("", true).await?;
        target.allowed = vec![read_serial(&target).await?];
        let outcome = smoke(target).await;
        assert!(outcome.is_err(), "a refused router was smoked");
        assert_eq!(commands(&handle), Vec::<String>::new(), "router writes");
        handle.shutdown().await?;
        Ok(())
    }
}
