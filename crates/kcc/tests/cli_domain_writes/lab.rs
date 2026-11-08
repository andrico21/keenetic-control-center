//! One fake router `lab-1` behind a hermetic CLI environment.

use core::error::Error;

use kcc_app::audit::read_entries;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, model::Profile};
use serde_json::Value;

use super::support::{Env, Run, router};

/// A fake KN-1811 named `lab-1` and the CLI environment pointing at it.
pub(crate) struct Lab {
    /// The CLI environment.
    pub env: Env,
    /// The fake router.
    pub fake: Handle,
}

impl Lab {
    /// Starts the fake and writes `kcc.toml` with `cli` (a `[cli]` table body or empty).
    pub(crate) async fn spawn(cli: &str) -> Result<Self, Box<dyn Error>> {
        Self::with_faults(cli, FaultInjection::default()).await
    }

    /// Starts a CLI fixture with router fault injection.
    pub(crate) async fn with_faults(
        cli: &str,
        faults: FaultInjection,
    ) -> Result<Self, Box<dyn Error>> {
        let (address, fake) = FakeRouter::builder(Profile::default())
            .faults(faults)
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let section = if cli.is_empty() {
            String::new()
        } else {
            format!("[cli]\n{cli}\n\n")
        };
        env.write_config(&format!("{section}{}", router("lab-1", address, &password)))?;
        Ok(Self { env, fake })
    }

    /// Runs `kcc <args>`.
    pub(crate) fn run(&self, args: &[&str]) -> Result<Run, Box<dyn Error>> {
        self.env.kcc(args)
    }

    /// Runs `kcc --json <args>`, requires exit 0 and returns the JSON document.
    pub(crate) fn json(&self, args: &[&str]) -> Result<Value, Box<dyn Error>> {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let run = self.env.kcc(&all)?;
        assert_eq!(run.code, 0_i32, "kcc {args:?}: {run:?}");
        Ok(serde_json::from_str(&run.stdout)?)
    }

    /// Every audit entry, rendered, for secret scans.
    pub(crate) fn audit_text(&self) -> Result<String, Box<dyn Error>> {
        Ok(format!("{:?}", read_entries(&self.env.state_dir())?))
    }

    /// Stops the fake router.
    pub(crate) async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        self.fake.shutdown().await?;
        Ok(())
    }
}
