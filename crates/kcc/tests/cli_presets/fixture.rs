//! Two fake routers: `fake-a` holding a saved DNS upstream, `fake-b` a migration target.

use core::{error::Error, net::SocketAddr};

use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, migration, model::Profile};
use secrecy::SecretString;
use serde_json::Value;

use super::support::{Env, Run, TestResult, router};

/// The `dns-secure` line `fake-a` holds in its startup configuration.
pub(crate) const UPSTREAM: &str = "dns-proxy tls upstream 1.1.1.1 853";

/// The routers and the hermetic environment registering them.
pub(crate) struct Pair {
    /// Configuration, state and master key.
    pub env: Env,
    /// `fake-a`.
    pub source: Handle,
    /// `fake-b`.
    pub target: Handle,
    /// The `[[routers]]` entries of both routers.
    pub routers: String,
}

impl Pair {
    /// Serves `fake-a` (default profile) and `fake-b` (`target`, router mode) and
    /// registers both.
    pub(crate) async fn start(target_profile: Profile) -> Result<Self, Box<dyn Error>> {
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let (source_address, source) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(local)
            .await?;
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let (target_address, target) = FakeRouter::builder(target_profile)
            .build()?
            .with_migration(scenario)
            .serve(local)
            .await?;
        seed(source_address).await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let routers = format!(
            "{}{}",
            router("fake-a", source_address, &password),
            router("fake-b", target_address, &password)
        );
        env.write_config(&routers)?;
        Ok(Self {
            env,
            source,
            target,
            routers,
        })
    }

    /// Rewrites `kcc.toml` with a `[cli]` section and both routers.
    pub(crate) fn with_cli(&self, cli: &str) -> TestResult {
        self.env
            .write_config(&format!("[cli]\n{cli}\n\n{}", self.routers))
    }

    /// Requests both routers received.
    pub(crate) fn requests(&self) -> (u64, u64) {
        (self.source.request_count(), self.target.request_count())
    }

    /// Runs `kcc --json copy --from fake-a --to fake-b --groups dns-secure --yes <extra>`.
    pub(crate) fn copy(&self, extra: &[&str]) -> Result<Run, Box<dyn Error>> {
        let mut args = vec![
            "--json",
            "copy",
            "--from",
            "fake-a",
            "--to",
            "fake-b",
            "--groups",
            "dns-secure",
            "--yes",
        ];
        args.extend_from_slice(extra);
        self.env.kcc(&args)
    }

    /// Stops both routers.
    pub(crate) async fn stop(self) -> TestResult {
        self.source.shutdown().await?;
        self.target.shutdown().await?;
        Ok(())
    }
}

/// Saves `UPSTREAM` on the router at `address`.
async fn seed(address: SocketAddr) -> TestResult {
    let url = format!("http://{address}").parse::<RouterUrl>()?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let client = RciClient::connect_with(url, credentials, options).await?;
    drop(client.parse(UPSTREAM).await?);
    drop(client.parse("system configuration save").await?);
    Ok(())
}

/// The JSON document a `--json` run printed on stdout.
pub(crate) fn stdout_json(run: &Run) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&run.stdout)?)
}
