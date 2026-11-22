//! The `entware` toolset over a real session: visibility and the live gates, the safety
//! gates of every operation, the `opkg` settings, the setup job, and the Entware drive
//! acknowledgement of `kcc_storage_write`.
extern crate alloc;

#[expect(
    dead_code,
    reason = "the shared MCP session support; this suite needs part of it"
)]
#[path = "support/lab.rs"]
mod lab;

#[path = "entware_tools/gating.rs"]
mod gating;
#[path = "entware_tools/helpers.rs"]
mod helpers;
#[path = "entware_tools/settings.rs"]
mod settings;
#[path = "entware_tools/setup.rs"]
mod setup;
#[path = "entware_tools/storage.rs"]
mod storage;
#[path = "entware_tools/visibility.rs"]
mod visibility;
