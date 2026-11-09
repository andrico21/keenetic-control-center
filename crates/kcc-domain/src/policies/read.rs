//! Connection-policy reads.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "asynchronous router reads are not inline candidates"
)]

use super::model::PolicyState;
use crate::{Result, RouterCtx, read_show};

/// Reads all configured connection policies.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn policies(router: &RouterCtx) -> Result<Vec<PolicyState>> {
    read_show(&router.client, &["show", "ip", "policy"]).await
}
