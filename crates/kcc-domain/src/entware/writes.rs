//! The `opkg` settings changes: the catalog body, the CLI line and the `show rc` `opkg`
//! read-back of each.

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::Risk;
use serde_json::{Value, json};

use super::models::TimezoneSetting;
use crate::{
    ChangeOp, OperationDescriptor, Result, RouterCtx, descriptor, planning::validate,
    request_words::negated,
};

/// Entware write inventory: the guided setup's `opkg disk`, its removal and the settings.
pub(super) const OPERATIONS: &[OperationDescriptor] = &[
    descriptor::operation(
        "setup",
        "opkg disk",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::operation(
        "remove",
        "opkg disk",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::write("chroot", "opkg chroot"),
    descriptor::write("timezone", "opkg timezone"),
    descriptor::operation(
        "initrc",
        "opkg initrc",
        Risk::Destructive,
        Permission::Destructive,
    ),
    descriptor::operation(
        "dns_override",
        "opkg dns-override",
        Risk::Management,
        Permission::Write,
    ),
];

/// One `opkg` settings change, its arguments already checked.
pub(super) enum OpkgChange<'change> {
    /// `opkg chroot`, or its removal.
    Chroot(bool),
    /// `opkg dns-override`, or its removal.
    DnsOverride(bool),
    /// `opkg timezone auto` or `opkg timezone <name>`.
    Timezone(TimezoneSetting),
    /// `opkg initrc <path>`.
    Initrc(&'change str),
    /// `no opkg disk`.
    RemoveDisk,
}

impl OpkgChange<'_> {
    /// The catalog command path.
    const fn path(&self) -> &'static str {
        match self {
            Self::Chroot(_) => "opkg chroot",
            Self::DnsOverride(_) => "opkg dns-override",
            Self::Timezone(_) => "opkg timezone",
            Self::Initrc(_) => "opkg initrc",
            Self::RemoveDisk => "opkg disk",
        }
    }

    /// The catalog request body.
    fn body(&self) -> Value {
        match self {
            Self::Chroot(true) | Self::DnsOverride(true) => json!({}),
            Self::Chroot(false) | Self::DnsOverride(false) | Self::RemoveDisk => json!({"no":true}),
            Self::Timezone(TimezoneSetting::Auto) => json!({"timezone":"auto"}),
            Self::Timezone(TimezoneSetting::Named(name)) => json!({"timezone":name}),
            Self::Initrc(path) => json!({"path":path}),
        }
    }

    /// The CLI line of the request `body`.
    fn line(&self, body: &Value) -> String {
        match self {
            Self::Chroot(_) | Self::DnsOverride(_) | Self::RemoveDisk => {
                negated(body, self.path().to_owned())
            }
            Self::Timezone(TimezoneSetting::Auto) => "opkg timezone auto".to_owned(),
            Self::Timezone(TimezoneSetting::Named(name)) => format!("opkg timezone {name}"),
            Self::Initrc(path) => format!("opkg initrc {path}"),
        }
    }

    /// The read-back of the changed field of `show rc` `opkg`.
    fn readback(&self) -> VerificationSpec {
        let path = vec!["show".to_owned(), "rc".to_owned(), "opkg".to_owned()];
        let (field, expected) = match self {
            Self::Chroot(enabled) => ("/chroot", enabled.then_some(json!(true))),
            Self::DnsOverride(enabled) => ("/dns-override", enabled.then_some(json!(true))),
            Self::Timezone(TimezoneSetting::Auto) => ("/timezone/auto", Some(json!(true))),
            Self::Timezone(TimezoneSetting::Named(name)) => {
                ("/timezone/timezone", Some(json!(name)))
            }
            Self::Initrc(script) => ("/initrc/path", Some(json!(script))),
            Self::RemoveDisk => ("/disk", None),
        };
        expected.map_or_else(
            || {
                VerificationSpec::presence(
                    path.clone(),
                    field.to_owned(),
                    PresencePredicate::Absent,
                )
            },
            |value| VerificationSpec::new(path.clone(), field.to_owned(), value),
        )
    }

    /// The risk class and the permission the change needs.
    const fn class(&self) -> (Risk, Permission) {
        match self {
            Self::Chroot(_) | Self::Timezone(_) => (Risk::Write, Permission::Write),
            Self::DnsOverride(_) => (Risk::Management, Permission::Write),
            Self::Initrc(_) | Self::RemoveDisk => (Risk::Destructive, Permission::Destructive),
        }
    }
}

/// `change` validated against the router's catalog, with its line and read-back.
///
/// # Errors
///
/// Returns [`crate::DomainError::Validation`] when the catalog refuses the request, and
/// [`crate::DomainError::Workflow`] when the line does not render it.
pub(super) fn plan(router: &RouterCtx, change: &OpkgChange<'_>) -> Result<ChangeOp> {
    let body = change.body();
    let validated = validate(router, change.path(), &body)?;
    let (risk, permission) = change.class();
    let mut operation = ChangeOp::new(Vec::new(), vec![change.readback()], risk, permission, false);
    operation.push(ValidatedCli::new(change.line(&body), validated)?);
    Ok(operation)
}
