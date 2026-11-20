//! Router log collection, parsing, deduplication, and forwarding.

mod batch;
pub mod dedupe;
mod destination;
pub mod elastic_sink;
pub mod format;
mod loki_reply;
pub mod parser;
pub mod pipeline;
mod pipeline_delivery;
pub mod queue;
pub mod readers;
pub mod redact;
pub mod retry;
pub mod runtime;
pub mod service;
pub mod sink;
pub(crate) mod sink_http;
pub mod types;
