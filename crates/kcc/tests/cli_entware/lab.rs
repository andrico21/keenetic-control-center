//! One fake router `lab-1` behind a hermetic CLI environment, for the Entware commands.

use core::{error::Error, net::SocketAddr};

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder, Handle, migration,
    model::{Firmware, Model, Profile},
};
use serde_json::{Value, json};

use super::support::{Env, Run, router};

/// The KN-1811 fixture drive, as `kcc entware status` lists it.
pub(crate) const DRIVE: &str = "fixture-media:/";

/// The 64-bit ARM installer of the plan's closed table, independent of the code under test.
pub(crate) const AARCH64_URL: &str =
    "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz";

/// The little-endian MIPS installer.
pub(crate) const MIPSEL_URL: &str =
    "https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz";

/// The arm and disarm lines of the fail-safe timer of a router in `router` mode.
pub(crate) const ARM: &str = "system configuration fail-safe timer reboot 300";
/// See [`ARM`].
pub(crate) const DISARM: &str = "no system configuration fail-safe timer";

/// The line of a configuration save.
pub(crate) const SAVE: &str = "system configuration save";

/// A fake router `lab-1` and the CLI environment pointing at it.
pub(crate) struct Lab {
    /// The CLI environment.
    pub env: Env,
    /// The fake router.
    pub fake: Handle,
    /// The fake router's address.
    pub address: SocketAddr,
}

/// What the fake router reports.
#[derive(Clone, Copy)]
pub(crate) enum Router {
    /// A KN-1811 on 5.1 (`aarch64`) with the `opkg` and `ext` components installed.
    Kn1811,
    /// A KN-1010 on 5.1 (`mips`) with the `opkg` and `ext` components installed.
    Kn1010,
}

impl Lab {
    /// A KN-1811 as the CLI role `role`.
    pub(crate) async fn spawn(role: &str) -> Result<Self, Box<dyn Error>> {
        Self::serve(Router::Kn1811, role).await
    }

    /// Serves `model` in `router` mode and configures it as `lab-1` for the CLI role `role`.
    pub(crate) async fn serve(model: Router, role: &str) -> Result<Self, Box<dyn Error>> {
        let (hardware, profile, arch) = match model {
            Router::Kn1811 => ("KN-1811", Model::Kn1811, "aarch64"),
            Router::Kn1010 => ("KN-1010", Model::Kn1010, "mips"),
        };
        let builder = FakeRouter::builder(Profile::latest(profile))
            .show_fixture("version", version(hardware, arch, COMPONENTS));
        Self::build(builder, role).await
    }

    /// Serves `builder` in `router` mode and configures it as `lab-1` for the CLI role
    /// `role`.
    pub(crate) async fn build(
        builder: FakeRouterBuilder,
        role: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let (address, fake) = builder
            .reached_directly()
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        env.write_config(&format!(
            "[cli]\nrole = {role:?}\n\n{}",
            router("lab-1", address, &password)
        ))?;
        Ok(Self { env, fake, address })
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

    /// Every parser line the router received, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.fake
            .request_log()
            .iter()
            .flat_map(|record| {
                record
                    .commands()
                    .flatten()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Stops the fake router.
    pub(crate) async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        self.fake.shutdown().await?;
        Ok(())
    }
}

/// `key` in English with `args`.
pub(crate) fn en(key: MessageKey, args: &[(&'static str, &str)]) -> String {
    let mut fluent = FluentArgs::new();
    for &(name, value) in args {
        fluent.set(name, value.to_owned());
    }
    tr(Locale::En, key, Some(&fluent))
}

/// The refusal text of an unconfirmed change on `lab-1`.
pub(crate) fn unconfirmed() -> String {
    en(keys::CLI_CONFIRM_MISSING, &[("router", "lab-1")])
}

/// The installed components of [`Lab::serve`]'s routers.
pub(crate) const COMPONENTS: &str = "base,usb,storage,opkg,ext";

/// A 5.1 `show version` of `hardware` reporting `arch` and the installed `components`.
pub(crate) fn version(hardware: &str, arch: &str, components: &str) -> Value {
    json!({
        "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
        "model": "Keenetic", "device": "Keenetic", "hw_id": hardware,
        "hw_version": "10000000", "hw_type": "router", "sandbox": "stable",
        "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.", "series": "KN",
        "region": "EA", "arch": arch,
        "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
        "ndw": {"components": components, "features": "wifi2ghz"}
    })
}
