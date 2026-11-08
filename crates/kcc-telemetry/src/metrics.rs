//! Prometheus exporter.
//!
//! The exporter adds no poller of its own: [`service::MetricsExporter::watch`] registers a
//! permanent metrics subscription with the shared [`kcc_app::poller::Poller`], and a scrape
//! renders only the cached snapshots (the scrape collector never calls a router). Data
//! older than 3 polling intervals is omitted and `keenetic_up` becomes 0.
//!
//! The kit serves the registry on a separate plaintext, unauthenticated `/metrics`
//! listener, which is why `[metrics] bind` stays on loopback unless
//! `allow_non_loopback = true`.

pub mod catalogue;
mod clients;
mod collector;
pub mod docs;
pub mod failure;
pub mod instrumentation;
mod interfaces;
mod json;
pub mod registry_follow;
pub mod service;
mod sink;
mod system;
pub mod web_sessions;
