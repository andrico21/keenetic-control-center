//! The presets pages over HTTP against fake routers: capturing a preset, applying it,
//! copying settings once, and the guards and redaction around them.

#[path = "presets_pages/apply.rs"]
mod apply;
#[path = "presets_pages/apply_abandoned.rs"]
mod apply_abandoned;
#[path = "presets_pages/capture.rs"]
mod capture;
#[path = "presets_pages/copy.rs"]
mod copy;
#[path = "presets_pages/flow.rs"]
mod flow;
#[path = "presets_pages/guards.rs"]
mod guards;
#[path = "presets_pages/off_runtime.rs"]
mod off_runtime;
#[path = "presets_pages/options.rs"]
mod options;
#[path = "presets_pages/preview.rs"]
mod preview;
#[path = "presets_pages/records.rs"]
mod records;
#[path = "presets_pages/retention.rs"]
mod retention;
#[path = "presets_pages/scope.rs"]
mod scope;
#[path = "presets_pages/secret_retention.rs"]
mod secret_retention;
#[path = "presets_pages/secrets.rs"]
mod secrets;
#[path = "presets_pages/setup.rs"]
mod setup;
#[path = "presets_pages/strangers.rs"]
mod strangers;
#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;
