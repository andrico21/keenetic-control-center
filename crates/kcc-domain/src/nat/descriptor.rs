//! NAT operation inventory.

use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor, descriptor};

/// NAT reads.
const READS: &[OperationDescriptor] = &[
    descriptor::by_risk("forwards", "ip static", Risk::Read),
    descriptor::by_risk("interfaces", "ip nat", Risk::Read),
    descriptor::by_risk("sessions", "show ip nat", Risk::Read),
];
/// NAT writes.
const WRITES: &[OperationDescriptor] = &[
    descriptor::by_risk("forward", "ip static", Risk::Write),
    descriptor::by_risk("interface", "ip nat", Risk::Write),
];

/// NAT domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Nat,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};
