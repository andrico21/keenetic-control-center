//! Firewall operation inventory.

use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor, descriptor};

/// Firewall reads.
const READS: &[OperationDescriptor] = &[
    descriptor::by_risk("access_lists", "access-list", Risk::Read),
    descriptor::by_risk("upnp_redirects", "show upnp redirect", Risk::Read),
    descriptor::by_risk("ipv6_access_lists", "ipv6 access-list", Risk::Read),
];
/// Firewall writes.
const WRITES: &[OperationDescriptor] = &[
    descriptor::by_risk("rule", "access-list permit", Risk::Write),
    descriptor::by_risk("binding", "interface ip access-group", Risk::Write),
];

/// Firewall domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Firewall,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};
