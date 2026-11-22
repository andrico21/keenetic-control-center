//! Where a page's write is described: a write a domain's descriptor lists, or one a
//! domain plans without listing it.

use kcc_domain::DomainDescriptor;

use super::Described;

/// Where a page's write is described.
#[derive(Debug, Clone, Copy)]
pub(super) enum Source {
    /// The write `name` of a domain's descriptor.
    Listed(&'static DomainDescriptor, &'static str),
    /// A write a domain plans that its descriptor does not list.
    Planned(Described),
}

impl Source {
    /// What running the write takes; `None` when the descriptor does not list it.
    pub(super) fn described(self) -> Option<Described> {
        match self {
            Self::Listed(domain, name) => domain
                .write_ops
                .iter()
                .find(|operation| operation.name == name)
                .map(|operation| Described {
                    catalog_path: operation.catalog_path,
                    permission: operation.permission,
                    risk: operation.risk,
                }),
            Self::Planned(described) => Some(described),
        }
    }
}
