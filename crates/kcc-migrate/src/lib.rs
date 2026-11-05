//! Configuration migration between router firmware generations.

#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public APIs are exercised by integration tests and downstream crates"
    )
)]

extern crate alloc;

pub mod inventory;
pub mod maps;
pub mod rules;
pub mod source;
