//! The Bot API client's DNS resolver: it drops every address no outbound-policy setting
//! could admit (cloud metadata, unspecified, multicast, broadcast and their IPv6 forms).

use alloc::sync::Arc;
use core::{
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
};

use kcc_rci::outbound::never_admitted;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::lookup_host;

/// A host-name lookup that replaces the system resolver.
type Lookup = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

/// The resolver error when no resolved address is left after filtering.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("no resolved address of the Bot API host is admitted")]
pub(super) struct AddressRefused;

/// Resolves host names and keeps only addresses that some outbound-policy setting could
/// admit; fails when none is left.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct PolicyResolver {
    /// The replacement lookup; the system resolver when `None`.
    lookup: Option<Lookup>,
}

impl fmt::Debug for PolicyResolver {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyResolver")
            .field("system", &self.lookup.is_none())
            .finish()
    }
}

impl PolicyResolver {
    /// A resolver that asks the system resolver.
    #[inline]
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    /// A resolver that asks `lookup` instead of the system resolver, for tests that map
    /// made-up host names to addresses. The same address filter applies.
    #[inline]
    #[must_use]
    pub fn with_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Vec<IpAddr> + Send + Sync + 'static,
    {
        Self {
            lookup: Some(Arc::new(lookup)),
        }
    }
}

impl Resolve for PolicyResolver {
    #[inline]
    fn resolve(&self, name: Name) -> Resolving {
        let replacement = self.lookup.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found: Vec<SocketAddr> = match replacement {
                Some(lookup) => lookup(&host)
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0))
                    .collect(),
                None => lookup_host((host.as_str(), 0_u16)).await?.collect(),
            };
            let kept: Vec<SocketAddr> = found
                .into_iter()
                .filter(|address| !never_admitted(address.ip()))
                .collect();
            if kept.is_empty() {
                let refused: Box<dyn Error + Send + Sync> = Box::new(AddressRefused);
                return Err(refused);
            }
            let addresses: Addrs = Box::new(kept.into_iter());
            Ok(addresses)
        })
    }
}
