//! Opaque projected answers from `show rc` and `show sc`.

use core::fmt;

use serde_json::Value;

use crate::{ConfigKind, RciError, RciResponse};

/// A configuration answer whose router envelope is inaccessible to callers.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct ConfigurationAnswer {
    /// Projected configuration tree without its router envelope.
    tree: Value,
}

impl fmt::Debug for ConfigurationAnswer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationAnswer")
    }
}

impl ConfigurationAnswer {
    /// Returns the requested running- or startup-configuration tree.
    #[inline]
    #[must_use]
    pub const fn configuration_tree(&self) -> &Value {
        &self.tree
    }

    /// Projects a decoded response into the requested configuration tree.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Decode`] when the router omits the requested configuration envelope.
    pub(crate) fn from_response(
        response: &RciResponse,
        kind: ConfigKind,
    ) -> Result<Self, RciError> {
        let pointer = match kind {
            ConfigKind::Startup => "/show/sc",
            ConfigKind::Running => "/show/rc",
        };
        let tree = response
            .value
            .pointer(pointer)
            .cloned()
            .ok_or(RciError::Decode)?;
        Ok(Self { tree })
    }
}
