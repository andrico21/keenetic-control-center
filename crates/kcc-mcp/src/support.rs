//! Shared boundary validation, result shaping, error mapping, routing, and access helpers.

pub(crate) mod access;
pub(crate) mod audit;
pub(crate) mod blocking;
pub(crate) mod call;
pub(crate) mod errors;
pub(crate) mod gates;
pub(crate) mod names;
pub(crate) mod plain;
pub(crate) mod principal;
pub(crate) mod raw_change;
pub(crate) mod route;
pub(crate) mod scrub;
pub(crate) mod shape;
pub(crate) mod truncate;
pub(crate) mod validate;
