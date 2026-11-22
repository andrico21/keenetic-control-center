//! The Entware page and the storage page's Entware drive warnings against the fake router.
//!
//! What each role sees and may do on a router that can run Entware and on one that cannot,
//! the settings changes read back, the confirmations each change asks for, the setup job
//! followed to its end, and the second acknowledgement of the drive Entware runs from.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

use kcc_testkit::{
    FakeRouter, FakeRouterBuilder,
    model::{Firmware, Model, Profile},
};
use serde_json::{Value, json};

use crate::support::{
    build::Setup,
    outcome::TestResult,
    web::{Fixture, ROUTER},
};

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/system/entware";

/// The drive the KN-1811 fixture offers Entware.
pub(crate) const DRIVE: &str = "fixture-media:/";

/// A KN-1811 5.1 `show version` reporting `arch` and the installed `components`.
fn version(arch: &str, components: &str) -> Value {
    json!({
        "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
        "model": "Keenetic Ultra", "device": "Ultra", "hw_id": "KN-1811",
        "hw_version": "10000000", "hw_type": "router", "sandbox": "stable",
        "vendor": "Keenetic", "manufacturer": "Keenetic Ltd.", "series": "KN",
        "region": "EA", "arch": arch,
        "ndm": {"exact": "0-00000000", "cdate": "1 Jan 2026"},
        "ndw": {"components": components, "features": "wifi2ghz"}
    })
}

/// A fake `model` on its latest firmware.
pub(crate) fn model(model: Model) -> FakeRouterBuilder {
    FakeRouter::builder(Profile::latest(model)).reached_directly()
}

/// A KN-1811 on 5.1 that already has the `opkg` and `ext` components.
pub(crate) fn ready() -> FakeRouterBuilder {
    model(Model::Kn1811).show_fixture("version", version("aarch64", "base,usb,storage,opkg,ext"))
}

/// The router pages over `fake`, with a Russian-speaking viewer beside the default
/// accounts.
///
/// # Errors
///
/// Returns the fake router's or the Web UI's setup failure.
pub(crate) async fn over(fake: FakeRouterBuilder) -> TestResult<Fixture> {
    let mut setup = Setup {
        routers: vec![(ROUTER, fake.build()?)],
        ..Setup::default()
    };
    setup.accounts.push(("russian", "viewer", Some("ru")));
    setup.build().await
}

/// Every command line the router received after its first `before` requests.
pub(crate) fn heard_since(fixture: &Fixture, before: usize) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .iter()
        .skip(before)
        .flat_map(|record| {
            record
                .commands()
                .flatten()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether the router received a command line containing `needle`.
pub(crate) fn heard(fixture: &Fixture, needle: &str) -> bool {
    heard_since(fixture, 0)
        .iter()
        .any(|line| line.contains(needle))
}

/// How many requests the router received so far.
pub(crate) fn mark(fixture: &Fixture) -> usize {
    fixture.handle().request_log().len()
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_entware/page.rs"]
mod page;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_entware/settings.rs"]
mod settings;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_entware/guards.rs"]
mod guards;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_entware/setup.rs"]
mod setup;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "system_entware/drives.rs"]
mod drives;
