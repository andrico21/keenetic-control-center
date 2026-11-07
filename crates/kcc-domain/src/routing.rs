//! Static-route configuration and routing-table views.
//!
//! Route removals must execute through [`change::remove_ipv4`] or
//! [`change::remove_ipv6`]; the `plan_remove_*` functions only build plans.

pub mod change;
pub mod descriptor;
pub mod model;
pub mod read;
