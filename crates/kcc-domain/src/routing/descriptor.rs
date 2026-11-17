//! Routing operation inventory.

use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor, descriptor};

/// Routing read operations.
const READS: &[OperationDescriptor] = &[
    descriptor::by_risk("ipv4_routes", "show ip route", Risk::Read),
    descriptor::by_risk("ipv6_routes", "show ipv6 route", Risk::Read),
];

/// Routing write operations.
const WRITES: &[OperationDescriptor] = &[
    descriptor::by_risk("ipv4_route", "ip route", Risk::Write),
    descriptor::by_risk("ipv6_route", "ipv6 route", Risk::Write),
];

/// Routing domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Routing,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};
