//! Connection-policy operation inventory.

use kcc_catalog::Risk;

use crate::{DomainDescriptor, DomainId, OperationDescriptor, descriptor};

/// Connection-policy reads.
const READS: &[OperationDescriptor] = &[descriptor::by_risk("list", "show ip policy", Risk::Read)];

/// Connection-policy writes.
const WRITES: &[OperationDescriptor] = &[
    descriptor::by_risk("policy", "ip policy", Risk::Write),
    descriptor::by_risk("description", "ip policy description", Risk::Write),
    descriptor::by_risk("permit", "ip policy permit", Risk::Write),
    descriptor::by_risk("multipath", "ip policy multipath", Risk::Write),
    descriptor::by_risk("route", "ip policy route", Risk::Write),
    descriptor::by_risk(
        "rate_limit_input",
        "ip policy rate-limit input",
        Risk::Write,
    ),
    descriptor::by_risk(
        "rate_limit_output",
        "ip policy rate-limit output",
        Risk::Write,
    ),
    descriptor::by_risk("standalone", "ip policy standalone", Risk::Write),
];

/// Connection-policy domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Policies,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};
