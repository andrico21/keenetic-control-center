//! Application services orchestrating domain, RCI and configuration.
// `dead_code_pub_in_binary` fires on the public API only in the lib unit-test
// binary; rustc accepts an expect for it at crate level alone.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

pub mod accounts;
pub mod api_key_use;
pub mod api_keys;
pub mod audit;
pub mod backups;
mod blocking;
pub mod brackets;
pub mod composition;
pub mod credentials;
pub mod entware_ssh;
pub mod jobs;
pub mod mcp_settings;
pub mod notify_store;
pub mod permissions;
pub mod persist;
pub mod poller;
pub mod pseudonym;
pub mod registry;
pub mod role_source;
pub mod schedules;
pub mod secrets;
pub mod settings;
pub mod workflow;
