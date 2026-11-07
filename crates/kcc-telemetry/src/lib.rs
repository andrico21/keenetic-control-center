//! Logging, metrics and tracing setup.

// `dead_code_pub_in_binary` sees public library APIs as unused only in the unit-test binary.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API is exercised by integration tests and the kcc binary"
    )
)]

extern crate alloc;

pub mod logs;
pub mod metrics;
