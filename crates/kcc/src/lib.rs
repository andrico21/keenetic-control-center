//! Keenetic Control Center process-level startup controls.

#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "the library test harness treats public startup APIs as binary-local"
    )
)]

pub mod cli;
pub mod privileges;
pub mod server;
mod server_migrations;
mod server_origins;
mod server_outbound;
mod server_tasks;
