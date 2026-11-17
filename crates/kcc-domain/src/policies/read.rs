//! Connection-policy reads.

use super::model::PolicyState;
use crate::{Result, RouterCtx, read_show};

/// Reads all configured connection policies.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn policies(router: &RouterCtx) -> Result<Vec<PolicyState>> {
    read_show(&router.client, &["show", "ip", "policy"]).await
}
