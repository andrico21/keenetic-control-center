//! Firewall operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor};

/// Firewall reads.
const READS: &[OperationDescriptor] = &[
    operation("access_lists", "access-list", Risk::Read),
    operation("upnp_redirects", "show upnp redirect", Risk::Read),
    operation("ipv6_access_lists", "ipv6 access-list", Risk::Read),
];
/// Firewall writes.
const WRITES: &[OperationDescriptor] = &[
    operation("rule", "access-list permit", Risk::Write),
    operation("binding", "interface ip access-group", Risk::Write),
    operation("ipv6_rule", "ipv6 access-list", Risk::Write),
];

/// Firewall domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Firewall,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Builds one firewall operation descriptor.
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
