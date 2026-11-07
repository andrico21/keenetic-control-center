//! NAT operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor};

/// NAT reads.
const READS: &[OperationDescriptor] = &[
    operation("forwards", "ip static", Risk::Read),
    operation("interfaces", "ip nat", Risk::Read),
    operation("sessions", "show ip nat", Risk::Read),
];
/// NAT writes.
const WRITES: &[OperationDescriptor] = &[
    operation("forward", "ip static", Risk::Write),
    operation("interface", "ip nat", Risk::Write),
];

/// NAT domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Nat,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Builds one NAT operation descriptor.
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
