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

pub mod persist;
pub mod secrets;
pub mod settings;
