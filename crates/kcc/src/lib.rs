//! Keenetic Control Center process-level startup controls.

#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "the library test harness treats public startup APIs as binary-local"
    )
)]

pub mod privileges;
