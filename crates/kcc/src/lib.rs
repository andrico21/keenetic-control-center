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
pub mod server_error;
mod server_metrics;
mod server_migrations;
mod server_notify;
mod server_origins;
mod server_outbound;
mod server_reload;
mod server_schedules;
mod server_services;
mod server_shutdown;
mod server_tasks;
mod server_tls_key;
mod server_web;
mod state_watch;
