//! What the SSH section shows of the router's answers.
//!
//! Package and service lists, a service's log and the job lines of a change show only
//! parsed values and counts, and every value the router sent is stripped of control
//! characters (templates escape the rest).

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_ssh::{grammar::ServiceName, parse::Package};
use kcc_telemetry::logs::types::LogRecord;
use serde_json::Value;

use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// `text` without control characters, such as terminal escapes.
pub(super) fn printable(text: &str) -> String {
    text.chars().filter(|found| !found.is_control()).collect()
}

/// One package row.
struct PackageRow {
    /// The package name.
    name: String,
    /// The installed version.
    version: String,
    /// The offered version.
    new_version: String,
}

/// The installed or upgradable packages.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh_packages.html")]
pub(super) struct PackagesView {
    /// Locale carrier.
    shell: Shell,
    /// How many, localized.
    count: String,
    /// The rows.
    rows: Vec<PackageRow>,
    /// Whether the list shows offered versions.
    upgradable: bool,
}

localized!(PackagesView);

impl PackagesView {
    /// `packages` in `locale`; with their offered versions when `upgradable`.
    pub(super) fn new(locale: Locale, packages: &[Package], upgradable: bool) -> Self {
        Self {
            shell: fragment_shell(locale),
            count: counted(
                locale,
                keys::WEB_SYSTEM_ENTWARE_SSH_PACKAGES_COUNT,
                packages.len(),
            ),
            rows: packages
                .iter()
                .map(|package| PackageRow {
                    name: package.name.as_str().to_owned(),
                    version: printable(&package.version),
                    new_version: package.new_version.as_deref().map_or_default(printable),
                })
                .collect(),
            upgradable,
        }
    }

    /// The list, the answer to the request that read it.
    pub(super) fn answer(&self) -> Response {
        errors::render(self)
    }
}

/// The services.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh_services.html")]
pub(super) struct ServicesView {
    /// Locale carrier.
    shell: Shell,
    /// How many, localized.
    count: String,
    /// The init script names.
    names: Vec<String>,
}

localized!(ServicesView);

impl ServicesView {
    /// `services` in `locale`.
    pub(super) fn new(locale: Locale, services: &[ServiceName]) -> Self {
        Self {
            shell: fragment_shell(locale),
            count: counted(
                locale,
                keys::WEB_SYSTEM_ENTWARE_SSH_SERVICES_COUNT,
                services.len(),
            ),
            names: services
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
        }
    }

    /// The list, the answer to the request that read it.
    pub(super) fn answer(&self) -> Response {
        errors::render(self)
    }
}

/// One service's log records.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh_log.html")]
pub(super) struct LogView {
    /// Locale carrier.
    shell: Shell,
    /// The title, naming the service.
    title: String,
    /// Each record's time and message.
    lines: Vec<(String, String)>,
}

localized!(LogView);

impl LogView {
    /// The log of `service` in `locale`: `records`, masked by the domain.
    pub(super) fn new(locale: Locale, service: &str, records: &[LogRecord]) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", service.to_owned());
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, keys::WEB_SYSTEM_ENTWARE_SSH_LOG_TITLE, Some(&args)),
            lines: records
                .iter()
                .map(|record| (record.ts.to_string(), printable(&record.message)))
                .collect(),
        }
    }

    /// The log, the answer to the request that read it.
    pub(super) fn answer(&self) -> Response {
        errors::render(self)
    }
}

/// `count` items said with `key` in `locale`.
fn counted(locale: Locale, key: MessageKey, count: usize) -> String {
    let mut args = FluentArgs::new();
    args.set("value", count.to_string());
    tr(locale, key, Some(&args))
}

/// The line of an Entware SSH change job's result, read back: the package's installed
/// version (or its removal), or the service's state.
pub(crate) fn ssh_line(progress: &Value, locale: Locale) -> Option<(String, bool)> {
    let text = |key, pairs: &[(&str, String)]| {
        let mut args = FluentArgs::new();
        for (name, said) in pairs {
            args.set(*name, said.clone());
        }
        tr(locale, key, Some(&args))
    };
    if let Some(package) = progress.get("package").and_then(Value::as_str) {
        let name = printable(package);
        let line = match progress.get("after").and_then(Value::as_str) {
            Some(version) => text(
                keys::WEB_SYSTEM_ENTWARE_SSH_JOB_INSTALLED,
                &[("name", name), ("value", printable(version))],
            ),
            None => text(keys::WEB_SYSTEM_ENTWARE_SSH_JOB_REMOVED, &[("name", name)]),
        };
        return Some((line, false));
    }
    let service = progress.get("service").and_then(Value::as_str)?;
    let key = match progress.get("state").and_then(Value::as_str)? {
        "running" => keys::WEB_SYSTEM_ENTWARE_SSH_RUNNING,
        "stopped" => keys::WEB_SYSTEM_ENTWARE_SSH_STOPPED,
        _ => return None,
    };
    Some((text(key, &[("name", printable(service))]), false))
}
