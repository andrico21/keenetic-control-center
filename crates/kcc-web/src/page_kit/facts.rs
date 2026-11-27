//! The catalog view of each router, selected from its firmware line and hardware id and
//! reused for [`FACTS_TTL`] seconds, so validating a request never contacts the router.

use alloc::collections::BTreeMap;
use std::sync::Mutex;

use kcc_app::registry::{RegistryError, RouterRegistry};
use kcc_catalog::{Catalog, ModelMatch};
use kcc_i18n::keys;
use kcc_rci::RciError;

use super::{
    family::Family,
    read_failure::{ReadProblem, rci_problem},
};
use crate::sync::lock;

/// Seconds detected router facts are reused before the router is asked again.
const FACTS_TTL: u64 = 600;

/// Cached facts by router id, with the Unix second they were detected.
type Entries = BTreeMap<String, (u64, RouterFacts)>;

/// What the pages know about one router.
#[derive(Clone)]
pub(crate) struct RouterFacts {
    /// Firmware- and model-specific command catalog.
    catalog: Catalog,
    /// Hardware id, such as `KN-1811`.
    hw_id: Option<String>,
}

/// Why the facts of a router are unknown.
#[derive(Debug)]
pub(crate) enum FactsError {
    /// The router could not be reached or identified: the router error that stopped it,
    /// or none when kcc could not even build a client for it.
    Unreachable(Option<RciError>),
    /// The router's firmware is older than every generated catalog.
    Unsupported,
}

impl FactsError {
    /// The failure of reaching the router through the registry, which `error` explains.
    pub(crate) fn unreachable(error: RegistryError) -> Self {
        let RegistryError::Rci(rci) = error else {
            return Self::Unreachable(None);
        };
        Self::Unreachable(Some(rci))
    }

    /// Why the page cannot use the router, in `family`'s words.
    pub(crate) fn problem(&self, family: Family) -> ReadProblem {
        match self {
            Self::Unreachable(Some(error)) => rci_problem(family, error),
            Self::Unreachable(None) => ReadProblem::from(family.unreachable()),
            Self::Unsupported => ReadProblem::from(keys::WEB_EXPLORER_UNSUPPORTED),
        }
    }

    /// The stable audit outcome id.
    pub(crate) const fn audit(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "unreachable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Detected facts by router id.
#[derive(Default)]
pub(crate) struct FactsCache {
    /// Cached entries.
    entries: Mutex<Entries>,
}

impl FactsCache {
    /// The facts of `router`: cached when younger than [`FACTS_TTL`] at `now`, otherwise
    /// detected through `registry` and cached.
    ///
    /// # Errors
    ///
    /// Returns [`FactsError`] when the router cannot be identified or its firmware has no
    /// catalog.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, detection only reads from the router.
    pub(crate) async fn get(
        &self,
        registry: &RouterRegistry,
        router: &str,
        now: u64,
    ) -> Result<RouterFacts, FactsError> {
        let cached = lock(&self.entries)
            .get(router)
            .filter(|(detected, _)| now.saturating_sub(*detected) < FACTS_TTL)
            .map(|(_, facts)| facts.clone());
        if let Some(facts) = cached {
            return Ok(facts);
        }
        let info = registry.poll_info(router).await.map_err(|error| {
            tracing::warn!(%error, router, "pages could not identify the router");
            FactsError::unreachable(error)
        })?;
        let catalog = Catalog::for_router(&info).map_err(|_error| FactsError::Unsupported)?;
        let facts = RouterFacts {
            catalog,
            hw_id: info.hw_id().map(str::to_owned),
        };
        drop(lock(&self.entries).insert(router.to_owned(), (now, facts.clone())));
        Ok(facts)
    }
}

impl RouterFacts {
    /// Firmware- and model-specific command catalog.
    pub(crate) const fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Hardware id, such as `KN-1811`.
    pub(crate) fn hw_id(&self) -> Option<&str> {
        self.hw_id.as_deref()
    }

    /// The catalog's model, or `None` when it combines every model.
    pub(crate) const fn catalog_model(&self) -> Option<&str> {
        match self.catalog.model_match() {
            ModelMatch::Exact(model) => Some(model.as_str()),
            ModelMatch::Union | _ => None,
        }
    }
}
