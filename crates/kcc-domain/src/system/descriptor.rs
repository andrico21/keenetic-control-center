//! System operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::{OperationDescriptor, descriptor};

/// System read inventory.
pub(super) const READS: &[OperationDescriptor] = &[
    descriptor::read("version", "show version"),
    descriptor::read("system", "show system"),
    descriptor::read("clock_date", "show clock date"),
    descriptor::read("ntp_status", "show ntp status"),
    descriptor::read("system_mode", "show system mode"),
];

/// System write inventory.
pub(super) const WRITES: &[OperationDescriptor] = &[
    descriptor::operation(
        "hostname",
        "system hostname",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "domainname",
        "system domainname",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "description",
        "system description",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "timezone",
        "system clock timezone",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation("ntp_server", "ntp server", Risk::Write, Permission::Write),
    descriptor::operation("ntp_master", "ntp master", Risk::Write, Permission::Write),
    descriptor::operation(
        "ntp_sync_period",
        "ntp sync-period",
        Risk::Write,
        Permission::Write,
    ),
    descriptor::operation(
        "reboot",
        "system reboot",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::operation(
        "factory_reset",
        "system configuration factory-reset",
        Risk::Destructive,
        Permission::Destructive,
    ),
];
