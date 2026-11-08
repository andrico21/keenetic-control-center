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
pub mod credentials;
pub mod jobs;
pub mod permissions;
pub mod persist;
pub mod poller;
pub mod registry;
pub mod role_source;
pub mod secrets;
pub mod settings;
pub mod workflow;
