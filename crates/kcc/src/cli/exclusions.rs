//! Registry write operations the CLI deliberately does not offer, each with its reason.
//!
//! An entry here is a documented gap, not a silent one: the coverage test fails when a
//! registry write operation has neither a subcommand in [`super::coverage::EXPOSED`] nor
//! an entry here, and when an entry names an operation the registry no longer has.

use kcc_domain::DomainId;

/// One registry write operation the CLI does not offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Exclusion {
    /// The curated domain.
    pub domain: DomainId,
    /// The registry operation name.
    pub op: &'static str,
    /// Why the CLI does not offer it.
    pub reason: &'static str,
}

/// Every registry write operation the CLI does not offer.
pub const EXCLUDED: &[Exclusion] = &[Exclusion {
    domain: DomainId::Firewall,
    op: "ipv6_rule",
    reason: "kcc-domain has no planner or executor for IPv6 access-list rules (only the \
             catalog path is registered); the MCP tools and the Web UI do not offer it either, \
             and a CLI shape would invent the rule semantics",
}];
