//! The router's firewall as the page reads it: through the firewall domain, with a read
//! that failed told as the page tells it.

use kcc_domain::{
    RouterCtx,
    firewall::{lists::Firewall, read},
};

use crate::page_kit::read_failure::{ReadProblem, domain_problem};

/// The router's firewall, from its running configuration.
///
/// # Errors
///
/// Returns why the configuration could not be read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn read(domain: &RouterCtx) -> Result<Firewall, ReadProblem> {
    read::firewall(domain).await.map_err(|error| {
        tracing::warn!(%error, "firewall page: running configuration unavailable");
        domain_problem(&error)
    })
}
