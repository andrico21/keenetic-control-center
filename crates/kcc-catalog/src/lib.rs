//! Command and parameter catalog for the router RCI surface.

#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "the generated public catalog table is consumed by downstream crates, not this crate's unit-test harness"
    )
)]

/// Generated embedded catalog artifacts.
pub mod generated;
