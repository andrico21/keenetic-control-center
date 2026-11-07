//! Routing operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor};

/// Routing read operations.
const READS: &[OperationDescriptor] = &[
    operation("ipv4_routes", "show ip route", Risk::Read),
    operation("ipv6_routes", "show ipv6 route", Risk::Read),
];

/// Routing write operations.
const WRITES: &[OperationDescriptor] = &[
    operation("ipv4_route", "ip route", Risk::Write),
    operation("ipv6_route", "ipv6 route", Risk::Write),
];

/// Routing domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Routing,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Builds one routing operation descriptor.
const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission: if matches!(risk, Risk::Read) {
            Permission::Read
        } else {
            Permission::Write
        },
        persists_immediately: false,
    }
}
