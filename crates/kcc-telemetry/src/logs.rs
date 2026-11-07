//! Router log collection, parsing, deduplication, and forwarding.

pub mod dedupe;
pub mod elastic_sink;
pub mod format;
pub mod parser;
pub mod pipeline;
mod pipeline_delivery;
pub mod queue;
pub mod redact;
pub mod retry;
pub mod runtime;
pub mod service;
pub mod sink;
pub mod types;
