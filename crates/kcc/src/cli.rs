//! The `kcc` command-line interface.
//!
//! Every invocation acts as `cli:<OS username>` with the `[cli] role` and optional
//! `[cli] router_scope` globs, through the same `kcc-app` permission checks, change
//! workflow and audit log as the Web UI and MCP.

mod accounts;
mod api_keys;
pub mod args;
pub mod args_admin;
pub mod args_domains;
pub mod args_domains_net;
pub mod args_domains_wire;
pub mod args_fleet;
pub mod args_migrate;
mod change;
mod context;
mod dom_core;
mod dom_net;
mod dom_routes;
mod dom_wifi;
mod dom_wire;
mod domains;
pub mod entry;
mod exit;
mod exit_from;
mod files;
mod fleet;
mod issues;
mod migrate;
mod migrate_apply;
mod migrate_plan;
mod output;
mod persist;
mod principal;
mod rci;
mod redact;
mod routers;
mod secret;
mod tls;
