//! `KCC_*` environment overrides, generated from one table.
//!
//! Each row names the variable, the `section.field` it overrides and the
//! parser for its trimmed value. The same table yields the variable list
//! ([`NAMES`]) and the rows [`apply`] runs, so the two cannot drift.

use core::{net::SocketAddr, time::Duration};
use std::{
    env::{self, VarError},
    path::PathBuf,
};

use ipnet::IpNet;
use url::Url;

use super::{ClientLabel, Config, ConfigError, LogMode, OverrideReport, normalize_suffixes};

/// One override: the variable, the field it targets and how it is applied.
struct Row {
    /// Environment variable name.
    var: &'static str,
    /// Dotted config path, for the report.
    field: &'static str,
    /// Parses the trimmed value and stores it in the field.
    set: fn(&mut Config, &str) -> Result<(), String>,
}

/// Expands the table into [`NAMES`] and the two row groups around the
/// `[outbound] allowed_suffixes` normalization.
macro_rules! env_table {
    (
        before_suffix_check { $($pre_var:literal => $pre_section:ident.$pre_field:ident: $pre_parse:expr,)+ }
        after_suffix_check { $($post_var:literal => $post_section:ident.$post_field:ident: $post_parse:expr,)+ }
    ) => {
        /// Every `KCC_*` variable, in application order.
        pub(super) const NAMES: &[&str] = &[$($pre_var,)+ $($post_var,)+];
        /// Rows applied before the suffix normalization.
        const BEFORE_SUFFIX_CHECK: &[Row] =
            &[$(env_table!(@row $pre_var, $pre_section.$pre_field, $pre_parse),)+];
        /// Rows applied after the suffix normalization.
        const AFTER_SUFFIX_CHECK: &[Row] =
            &[$(env_table!(@row $post_var, $post_section.$post_field, $post_parse),)+];
    };
    (@row $var:literal, $section:ident.$field:ident, $parse:expr) => {
        Row {
            var: $var,
            field: concat!(stringify!($section), ".", stringify!($field)),
            set: |config, raw| {
                let parse: fn(&str) -> Result<_, String> = $parse;
                config.$section.$field = parse(raw)?;
                Ok(())
            },
        }
    };
}

env_table! {
    before_suffix_check {
        "KCC_WEB_ENABLED" => web.enabled: parse_bool,
        "KCC_WEB_SESSION_IDLE" => web.session_idle: parse_duration,
        "KCC_WEB_SESSION_ABSOLUTE" => web.session_absolute: parse_duration,
        "KCC_WEB_LOGIN_MAX_FAILURES" => web.login_max_failures: parse_number,
        "KCC_WEB_LOCKOUT" => web.lockout: parse_duration,
        "KCC_WEB_DEFAULT_LOCALE" => web.default_locale: parse_string,
        "KCC_WEB_PUBLIC_URL" => web.public_url:
            |raw| Url::parse(raw).map(Some).map_err(|error| error.to_string()),
        "KCC_MCP_HTTP_ENABLED" => mcp.http_enabled: parse_bool,
        "KCC_MCP_STDIO_ENABLED" => mcp.stdio_enabled: parse_bool,
        "KCC_MCP_STDIO_ROLE" => mcp.stdio_role: parse_string,
        "KCC_MCP_READ_ONLY" => mcp.read_only: parse_bool,
        "KCC_MCP_ALLOW_DESTRUCTIVE" => mcp.allow_destructive: parse_bool,
        "KCC_MCP_MAX_RESULT_BYTES" => mcp.max_result_bytes: parse_number,
        "KCC_MCP_TOOLSETS" => mcp.toolsets: |raw| Ok(split_list(raw)),
        "KCC_OUTBOUND_ALLOWED_NETWORKS" => outbound.allowed_networks: |raw| {
            split_list(raw)
                .into_iter()
                .map(|item| item.parse::<IpNet>().map_err(|error| error.to_string()))
                .collect()
        },
        "KCC_OUTBOUND_ALLOWED_SUFFIXES" => outbound.allowed_suffixes: |raw| Ok(split_list(raw)),
        "KCC_OUTBOUND_ALLOW_LOOPBACK" => outbound.allow_loopback: parse_bool,
    }
    after_suffix_check {
        "KCC_STATE_DIR" => state.dir: |raw| {
            if raw.is_empty() {
                Err("must not be empty".to_owned())
            } else {
                Ok(Some(PathBuf::from(raw)))
            }
        },
        "KCC_BACKUPS_KEEP_LAST" => backups.keep_last: parse_number,
        "KCC_BACKUPS_MAX_AGE" => backups.max_age: parse_duration,
        "KCC_AUDIT_RETENTION" => audit.retention: parse_duration,
        "KCC_CLI_ROLE" => cli.role: parse_string,
        "KCC_CLI_ROUTER_SCOPE" => cli.router_scope: |raw| Ok(split_list(raw)),
        "KCC_PRIVACY_REDACT_CLIENTS_IN_MCP" => privacy.redact_clients_in_mcp: parse_bool,
        "KCC_METRICS_ENABLED" => metrics.enabled: parse_bool,
        "KCC_METRICS_BIND" => metrics.bind:
            |raw| raw.parse::<SocketAddr>().map_err(|error| error.to_string()),
        "KCC_METRICS_ALLOW_NON_LOOPBACK" => metrics.allow_non_loopback: parse_bool,
        "KCC_METRICS_INTERVAL" => metrics.interval: parse_duration,
        "KCC_METRICS_HEAVY_INTERVAL" => metrics.heavy_interval: parse_duration,
        "KCC_METRICS_PER_CLIENT" => metrics.per_client: parse_bool,
        "KCC_METRICS_PER_CLIENT_MAX" => metrics.per_client_max: parse_number,
        "KCC_METRICS_PER_CLIENT_LABEL" => metrics.per_client_label: |raw| match raw {
            "name" => Ok(ClientLabel::Name),
            "pseudonym" => Ok(ClientLabel::Pseudonym),
            "mac" => Ok(ClientLabel::Mac),
            _ => Err("expected name, pseudonym or mac".to_owned()),
        },
        "KCC_LOGS_ENABLED" => logs.enabled: parse_bool,
        "KCC_LOGS_ROUTERS" => logs.routers: |raw| Ok(split_list(raw)),
        "KCC_LOGS_MODE" => logs.mode: |raw| match raw {
            "stream" => Ok(LogMode::Stream),
            "poll" => Ok(LogMode::Poll),
            _ => Err("expected stream or poll".to_owned()),
        },
        "KCC_LOGS_STREAM_INTERVAL" => logs.stream_interval: parse_duration,
        "KCC_LOGS_POLL_INTERVAL" => logs.poll_interval: parse_duration,
        "KCC_LOGS_REDACT_MACS" => logs.redact_macs: parse_bool,
        "KCC_LOGS_QUEUE_MAX" => logs.queue_max:
            |raw| raw.parse::<usize>().map_err(|error| error.to_string()),
    }
}

/// Applies every row whose variable `lookup` finds, in table order, and
/// normalizes `[outbound] allowed_suffixes` between the two row groups.
///
/// # Errors
///
/// [`ConfigError::Env`] for an unusable value, [`ConfigError::Invalid`] for a
/// bad suffix, or whatever `lookup` returns.
pub(super) fn apply<F>(config: &mut Config, lookup: F) -> Result<Vec<OverrideReport>, ConfigError>
where
    F: Fn(&str) -> Result<Option<String>, ConfigError>,
{
    let mut report = apply_rows(config, &lookup, BEFORE_SUFFIX_CHECK)?;
    normalize_suffixes(&mut config.outbound.allowed_suffixes)?;
    report.extend(apply_rows(config, &lookup, AFTER_SUFFIX_CHECK)?);
    Ok(report)
}

/// Applies `rows` in order and reports each override applied.
///
/// # Errors
///
/// [`ConfigError::Env`] for an unusable value, or whatever `lookup` returns.
fn apply_rows<F>(
    config: &mut Config,
    lookup: &F,
    rows: &[Row],
) -> Result<Vec<OverrideReport>, ConfigError>
where
    F: Fn(&str) -> Result<Option<String>, ConfigError>,
{
    let mut report = Vec::new();
    for row in rows {
        let Some(raw) = lookup(row.var)? else {
            continue;
        };
        (row.set)(config, raw.trim()).map_err(|reason| ConfigError::Env {
            var: row.var.to_owned(),
            reason,
        })?;
        report.push(OverrideReport {
            env_var: row.var.to_owned(),
            target_field: row.field.to_owned(),
            from_file: false,
            value: Some(raw),
        });
    }
    Ok(report)
}

/// Reads one variable from the process environment.
///
/// # Errors
///
/// [`ConfigError::Env`] when the value is not UTF-8.
pub(super) fn process_env(var: &str) -> Result<Option<String>, ConfigError> {
    match env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::Env {
            var: var.to_owned(),
            reason: "not valid UTF-8".to_owned(),
        }),
    }
}

/// Parses `true`/`false`/`1`/`0`.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("expected true, false, 1 or 0".to_owned()),
    }
}

/// Parses a humantime duration such as `30m` or `180d`.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_duration(raw: &str) -> Result<Duration, String> {
    humantime::parse_duration(raw).map_err(|error| error.to_string())
}

/// Parses an unsigned integer.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_number(raw: &str) -> Result<u32, String> {
    raw.parse::<u32>().map_err(|error| error.to_string())
}

/// Accepts any non-empty string.
///
/// # Errors
///
/// The reason the value was rejected.
fn parse_string(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        Err("must not be empty".to_owned())
    } else {
        Ok(raw.to_owned())
    }
}

/// Splits a comma-separated list, dropping empty items.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}
