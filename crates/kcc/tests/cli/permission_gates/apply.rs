//! The built-in operator applies presets: the recovery timer around the run is authorized
//! by `Migrate`, while a rollback finish still needs `Destructive`.

use core::{error::Error, net::SocketAddr};

use fluent_bundle::FluentArgs;
use kcc_app::{audit::read_entries, permissions::Permission};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, migration, model::Profile};
use secrecy::SecretString;

use super::{Env, TestResult, add_role_with_scope, commands_after, router};
use crate::support::Run;
#[cfg(target_os = "linux")]
use crate::{spawning, support};

/// The `dns-secure` line the source router holds.
const UPSTREAM: &str = "dns-proxy tls upstream 1.1.1.1 853";

/// A seeded source `src`, a router-mode target `lab-1`, and preset `office` captured from
/// `src` by the configuration's default role.
struct Pair {
    /// Configuration and state.
    env: Env,
    /// `src`.
    source: Handle,
    /// `lab-1`.
    target: Handle,
    /// The `[[routers]]` entries.
    routers: String,
}

impl Pair {
    /// Serves both routers, registers them and captures `office`.
    async fn start() -> Result<Self, Box<dyn Error>> {
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let (source_address, source) = FakeRouter::builder(Profile::default())
            .build()?
            .serve(local)
            .await?;
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let (target_address, target) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(local)
            .await?;
        seed(source_address).await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let routers = format!(
            "{}{}",
            router("src", source_address, &password),
            router("lab-1", target_address, &password)
        );
        env.write_config(&routers)?;
        let captured = env.kcc(&[
            "preset",
            "capture",
            "--from",
            "src",
            "--groups",
            "dns-secure",
            "--name",
            "office",
        ])?;
        assert_eq!(captured.code, 0_i32, "{captured:?}");
        Ok(Self {
            env,
            source,
            target,
            routers,
        })
    }

    /// Runs `preset apply office` onto `lab-1` as `role`, finishing with `finish`.
    fn apply(&self, role: &str, finish: &str) -> Result<Run, Box<dyn Error>> {
        self.env
            .write_config(&format!("[cli]\nrole = {role:?}\n{}", self.routers))?;
        self.env.kcc(&[
            "--router", "lab-1", "--json", "preset", "apply", "office", "--yes", "--finish", finish,
        ])
    }

    /// Requests both routers received.
    fn requests(&self) -> (u64, u64) {
        (self.source.request_count(), self.target.request_count())
    }

    /// Stops both routers.
    async fn stop(self) -> TestResult {
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

/// The built-in operator applies a preset and ends it unsaved or saved: the target's
/// command log runs arm, the preset's line, then disarm or commit.
// NOT cancel-safe: the fixture applies router settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_applies_a_preset_and_finishes_with_keep_and_with_save() -> TestResult {
    for (finish, closing) in [
        ("keep-unsaved", "no system configuration fail-safe timer"),
        ("save", "system configuration fail-safe commit"),
    ] {
        let pair = Pair::start().await?;
        let before = pair.target.request_log().len();

        let run = pair.apply("operator", finish)?;

        assert_eq!(run.code, 0_i32, "{finish}: {run:?}");
        let commands = commands_after(&pair.target, before);
        let arm = commands
            .iter()
            .position(|line| line == "system configuration fail-safe timer reboot 900")
            .ok_or_else(|| format!("{finish}: no arm in {commands:?}"))?;
        let line = commands
            .iter()
            .position(|sent| sent == UPSTREAM)
            .ok_or_else(|| format!("{finish}: no preset line in {commands:?}"))?;
        let closed = commands
            .iter()
            .rposition(|sent| sent == closing)
            .ok_or_else(|| format!("{finish}: no {closing:?} in {commands:?}"))?;
        assert!(arm < line && line < closed, "{finish}: {commands:?}");
        assert!(!pair.target.recovery_armed(), "{finish}: timer left armed");
        assert_eq!(
            pair.target.startup_config_text().contains(UPSTREAM),
            finish == "save",
            "{finish}: startup configuration"
        );
        let refused = read_entries(&pair.env.state_dir())?
            .into_iter()
            .filter(|entry| entry.action == "cli.refused")
            .count();
        assert_eq!(refused, 0, "{finish}: nothing refused");
        pair.stop().await?;
    }
    Ok(())
}

/// stack: a CLI command must run within Windows' 1 MiB main stack.
///
/// The operator's preset apply, the deepest command of the Windows suite, overflowed it
/// once the command dispatchers' unoptimized poll frames grew; Linux emulates the limit
/// with `ulimit -s`.
// NOT cancel-safe: the fixture applies router settings.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preset_apply_runs_within_a_one_mebibyte_main_stack() -> TestResult {
    let pair = Pair::start().await?;
    pair.env
        .write_config(&format!("[cli]\nrole = \"operator\"\n{}", pair.routers))?;

    let config = pair.env.path("kcc.toml");
    let kcc = [
        env!("CARGO_BIN_EXE_kcc"),
        "--config",
        config.to_str().ok_or("non-UTF-8")?,
    ];
    let apply = [
        "--router", "lab-1", "--json", "preset", "apply", "office", "--yes",
    ];
    let finish = ["--finish", "keep-unsaved"];
    let launcher = ["-c", "ulimit -s 1024 && exec \"$0\" \"$@\""];
    let args = [&launcher[..], &kcc, &apply, &finish].concat();

    let run = support::finish(spawning::spawn(&mut pair.env.launch("sh", &args))?)?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(!pair.target.recovery_armed(), "timer left armed");
    pair.stop().await
}

/// The operator's rollback finish and a viewer's apply are refused before either router
/// receives a request.
// NOT cancel-safe: the fixture captures a preset from the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_rollback_finish_and_viewer_apply_are_refused_before_any_router_request()
-> TestResult {
    let pair = Pair::start().await?;
    for (role, finish) in [("operator", "rollback"), ("viewer", "save")] {
        let before = pair.requests();

        let refused = pair.apply(role, finish)?;

        assert_eq!(refused.code, 10_i32, "{role}: {refused:?}");
        assert_eq!(pair.requests(), before, "{role}: router traffic");
    }
    let operator = pair.apply("operator", "rollback")?;
    assert!(
        operator.stderr.contains(&tr(
            Locale::En,
            keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE,
            None
        )),
        "the refusal names Destructive: {operator:?}"
    );
    let refusals = read_entries(&pair.env.state_dir())?
        .into_iter()
        .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
        .count();
    assert_eq!(refusals, 3, "each refusal is audited");
    pair.stop().await
}

/// A custom role with all apply permissions but scope `["other"]` applying to `lab-1`
/// exits 10 with the out-of-scope message and no empty permission list.
// NOT cancel-safe: the fixture applies router settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_role_with_all_apply_permissions_shows_router_out_of_scope() -> TestResult {
    let pair = Pair::start().await?;

    // Create a role with all apply permissions (Read, Migrate, Write, Save)
    // but only scoped to ["other"], not ["lab-1", "src"]
    add_role_with_scope(
        &pair.env,
        "scoped_operator",
        &[
            Permission::Read,
            Permission::Migrate,
            Permission::Write,
            Permission::Save,
        ],
        vec!["other".to_owned()],
    )?;

    let run = pair.apply("scoped_operator", "save")?;

    assert_eq!(run.code, 10_i32, "{run:?}");
    let mut router = FluentArgs::new();
    router.set("router", "lab-1");
    let out_of_scope = tr(Locale::En, keys::CLI_ROUTER_OUT_OF_SCOPE, Some(&router));
    assert!(
        run.stderr.contains(&out_of_scope),
        "the refusal names the router out of scope: {run:?}",
    );
    let mut nothing_missing = FluentArgs::new();
    nothing_missing.set("missing", "");
    assert!(
        !run.stderr.contains(&tr(
            Locale::En,
            keys::CLI_APPLY_RECOVERY_FORBIDDEN,
            Some(&nothing_missing)
        )),
        "no refusal with an empty permission list: {run:?}"
    );

    pair.stop().await
}
