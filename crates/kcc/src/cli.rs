//! The `kcc` command-line interface.
//!
//! Every invocation acts as `cli:<OS username>` with the `[cli] role` and optional
//! `[cli] router_scope` globs, through the same `kcc-app` permission checks, change
//! workflow and audit log as the Web UI and MCP.

mod accounts;
mod api_keys;
pub mod args;
pub mod args_admin;
pub mod args_dom_admin;
pub mod args_dom_dns;
pub mod args_dom_jobs;
pub mod args_dom_lan;
pub mod args_dom_link;
pub mod args_dom_vpn;
pub mod args_dom_vpn_server;
pub mod args_domains;
pub mod args_domains_net;
pub mod args_domains_wire;
pub mod args_fleet;
pub mod args_migrate;
pub mod args_router;
mod change;
mod closing;
mod context;
mod dom_admin;
mod dom_clients;
mod dom_core;
mod dom_dns;
mod dom_jobs;
mod dom_lan;
mod dom_link;
mod dom_mgmt;
mod dom_net;
mod dom_policies;
mod dom_routes;
mod dom_vpn;
mod dom_vpn_server;
mod dom_wifi;
mod dom_wire;
mod domains;
pub mod entry;
mod exit;
mod exit_from;
mod files;
mod fleet;
mod issues;
mod line_diff;
mod migrate;
mod migrate_apply;
mod migrate_plan;
mod notify;
mod outbound;
mod output;
mod persist;
pub mod preset;
mod principal;
mod rci;
mod redact;
mod router_edit;
mod router_secrets;
mod routers;
mod secret;
mod source_arg;
mod tls;
