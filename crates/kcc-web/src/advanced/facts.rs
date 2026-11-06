//! The catalog view of each router, selected from its firmware line and hardware id and
//! reused for [`FACTS_TTL`] seconds, so validating a request never contacts the router.

use alloc::collections::BTreeMap;
use std::sync::Mutex;

use kcc_app::registry::RouterRegistry;
use kcc_catalog::{Catalog, ModelMatch};
use kcc_domain::configuration::SafetyMode;
use kcc_rci::capabilities::SystemMode;

use super::lock;

/// Seconds detected router facts are reused before the router is asked again.
const FACTS_TTL: u64 = 600;

/// What the advanced pages know about one router.
#[derive(Clone)]
pub(crate) struct RouterFacts {
    /// Firmware- and model-specific command catalog.
    catalog: Catalog,
    /// How a management change is protected.
    mode: SafetyMode,
    /// Hardware id, such as `KN-1811`.
    hw_id: Option<String>,
}

/// Why the facts of a router are unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FactsError {
    /// The router could not be reached or identified.
    Unreachable,
    /// The router's firmware is older than every generated catalog.
    Unsupported,
}

/// Detected facts by router id, with the Unix second they were detected.
#[derive(Default)]
pub(crate) struct FactsCache {
    /// Cached entries.
    entries: Mutex<BTreeMap<String, (u64, RouterFacts)>>,
}

impl FactsCache {
    /// The facts of `router`: cached when younger than [`FACTS_TTL`] at `now`, otherwise
    /// detected through `registry` and cached.
    ///
    /// # Errors
    ///
    /// Returns [`FactsError`] when the router cannot be identified or its firmware has no
    /// catalog.
    // cancel-safe: detection only reads from the router.
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
            tracing::warn!(%error, router, "explorer could not identify the router");
            FactsError::Unreachable
        })?;
        let catalog = Catalog::for_router(&info).map_err(|_error| FactsError::Unsupported)?;
        let mode = match info.system_mode {
            None | Some(SystemMode::Router) => SafetyMode::Router,
            Some(_) => SafetyMode::ScheduledReboot,
        };
        let facts = RouterFacts {
            catalog,
            mode,
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

    /// How a management change is protected.
    pub(crate) const fn mode(&self) -> SafetyMode {
        self.mode
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
