//! System operation inventory.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::OperationDescriptor;

/// System read inventory.
pub(super) const READS: &[OperationDescriptor] = &[
    read_operation("version", "show version"),
    read_operation("system", "show system"),
    read_operation("clock_date", "show clock date"),
    read_operation("ntp_status", "show ntp status"),
    read_operation("system_mode", "show system mode"),
];

/// System write inventory.
pub(super) const WRITES: &[OperationDescriptor] = &[
    write_operation(
        "hostname",
        "system hostname",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "domainname",
        "system domainname",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "description",
        "system description",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "timezone",
        "system clock timezone",
        Risk::Write,
        Permission::Write,
    ),
    write_operation("ntp_server", "ntp server", Risk::Write, Permission::Write),
    write_operation("ntp_master", "ntp master", Risk::Write, Permission::Write),
    write_operation(
        "ntp_sync_period",
        "ntp sync-period",
        Risk::Write,
        Permission::Write,
    ),
    write_operation(
        "reboot",
        "system reboot",
        Risk::Destructive,
        Permission::Destructive,
    ),
    write_operation(
        "factory_reset",
        "system configuration factory-reset",
        Risk::Destructive,
        Permission::Destructive,
    ),
];

/// Builds a read descriptor.
const fn read_operation(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    write_operation(name, catalog_path, Risk::Read, Permission::Read)
}

/// Builds a write descriptor.
const fn write_operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
}
