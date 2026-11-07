//! Connection-policy operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor};

/// Connection-policy reads.
const READS: &[OperationDescriptor] = &[operation("list", "show ip policy", Risk::Read)];

/// Connection-policy writes.
const WRITES: &[OperationDescriptor] = &[
    operation("policy", "ip policy", Risk::Write),
    operation("description", "ip policy description", Risk::Write),
    operation("permit", "ip policy permit", Risk::Write),
    operation("multipath", "ip policy multipath", Risk::Write),
    operation("route", "ip policy route", Risk::Write),
    operation(
        "rate_limit_input",
        "ip policy rate-limit input",
        Risk::Write,
    ),
    operation(
        "rate_limit_output",
        "ip policy rate-limit output",
        Risk::Write,
    ),
    operation("standalone", "ip policy standalone", Risk::Write),
];

/// Connection-policy domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Policies,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Builds one connection-policy operation descriptor.
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
