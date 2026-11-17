//! Catalog validation and protected workflow conversion for DNS changes.

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Value, json};

use super::{DnsChange, FilterEngine, HttpsUpstream, RebindProtection, TlsUpstream};
use crate::{
    ChangeOp, DomainError, Result, RouterCtx, cli_token, planning::validate,
    request_words::negated, verification,
};

/// Validates a typed DNS change against the selected router catalog.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
pub(super) fn plan(router: &RouterCtx, change: &DnsChange) -> Result<ChangeOp> {
    let (path, body) = catalog_input(change);
    let validated = validate(router, path, &body)?;
    let line = if let DnsChange::FqdnInclude { name, address } = change {
        format!(
            "object-group fqdn {} include {}",
            cli_token::token(name)?,
            cli_token::token(address)?
        )
    } else if let DnsChange::FqdnExclude { name, address } = change {
        format!(
            "object-group fqdn {} exclude {}",
            cli_token::token(name)?,
            cli_token::token(address)?
        )
    } else if let DnsChange::FqdnDescription { name, description } = change {
        format!(
            "object-group fqdn {} description {}",
            cli_token::token(name)?,
            cli_token::quoted_text(description)?
        )
    } else {
        render_validated(&validated)?
    };
    let command = ValidatedCli::new(line, validated)?;
    let verify = match change {
        DnsChange::HttpsUpstream(upstream) => vec![VerificationSpec::new(
            vec!["show".to_owned(), "dns-proxy".to_owned()],
            "/https/upstream".to_owned(),
            Value::Array(vec![Value::Array(render_https_args(upstream))]),
        )],
        DnsChange::TlsUpstream(_)
        | DnsChange::FilterEngine(_)
        | DnsChange::FilterProfile { name: _ }
        | DnsChange::FilterProfileDescription {
            name: _,
            description: _,
        }
        | DnsChange::AssignHostPreset { host: _, preset: _ }
        | DnsChange::AssignHostProfile {
            host: _,
            profile: _,
        }
        | DnsChange::AssignInterfacePreset {
            interface: _,
            preset: _,
        }
        | DnsChange::AssignInterfaceProfile {
            interface: _,
            profile: _,
        }
        | DnsChange::Intercept { enabled: _ }
        | DnsChange::RebindProtect(_)
        | DnsChange::MaxTtl(_)
        | DnsChange::Route(_)
        | DnsChange::NameServer { address: _ }
        | DnsChange::StaticHost {
            domain: _,
            address: _,
        }
        | DnsChange::FqdnGroup { name: _ }
        | DnsChange::FqdnDescription {
            name: _,
            description: _,
        }
        | DnsChange::FqdnInclude {
            name: _,
            address: _,
        }
        | DnsChange::FqdnExclude {
            name: _,
            address: _,
        }
        | DnsChange::NextDnsHost { host: _, token: _ }
        | DnsChange::NextDnsInterface {
            interface: _,
            token: _,
        } => Vec::new(),
    };
    let mut operation = ChangeOp::new(Vec::new(), verify, Risk::Write, Permission::Write, false);
    operation.push(command);
    Ok(operation)
}

/// Converts validated DNS operations to protected CLI workflow input: the planned
/// commands, or a line rendered from each request of a plan built from requests alone.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when a field of a plan built from requests alone is
/// not one safe CLI word, [`DomainError::InvalidResponse`] when such a request is not a DNS
/// command, lacks a field, or when a command cannot be given a read-back of its own (a
/// secret-bearing command, or a line that is not exactly one configuration row), and
/// [`DomainError::Workflow`] when a rendered line does not match its request.
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let commands = if operation.commands.is_empty() {
        operation
            .requests
            .iter()
            .map(|validated| {
                Ok(ValidatedCli::new(
                    render_validated(validated)?,
                    validated.clone(),
                )?)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        operation.commands.clone()
    };
    verification::complete(CliChangeRequest::new(
        commands,
        operation.verify.clone(),
        operation.permission,
        json!({"domain":"dns"}),
    ))
}

/// The catalog path and body of one DNS change.
fn catalog_input(change: &DnsChange) -> (&'static str, Value) {
    let (path, mut body) = match change {
        DnsChange::TlsUpstream(value) => ("dns-proxy tls upstream", tls_body(value)),
        DnsChange::HttpsUpstream(value) => ("dns-proxy https upstream", https_body(value)),
        DnsChange::FilterEngine(engine) => (
            "dns-proxy filter engine",
            json!({"engine":engine_name(*engine)}),
        ),
        DnsChange::FilterProfile { name } => ("dns-proxy filter profile", json!({"name":name})),
        DnsChange::FilterProfileDescription { name, description } => (
            "dns-proxy filter profile description",
            json!({"name":name,"description":description}),
        ),
        DnsChange::AssignHostPreset { host, preset } => (
            "dns-proxy filter assign host preset",
            json!({"host":host,"preset":preset}),
        ),
        DnsChange::AssignHostProfile { host, profile } => (
            "dns-proxy filter assign host profile",
            json!({"host":host,"profile":profile}),
        ),
        DnsChange::AssignInterfacePreset { interface, preset } => (
            "dns-proxy filter assign interface preset",
            json!({"interface":interface,"preset":preset}),
        ),
        DnsChange::AssignInterfaceProfile { interface, profile } => (
            "dns-proxy filter assign interface profile",
            json!({"interface":interface,"profile":profile}),
        ),
        DnsChange::Intercept { enabled } => (
            "dns-proxy intercept enable",
            if *enabled {
                json!({})
            } else {
                json!({"no":true})
            },
        ),
        DnsChange::RebindProtect(mode) => (
            "dns-proxy rebind-protect",
            json!({"mode":rebind_name(*mode)}),
        ),
        DnsChange::MaxTtl(value) => (
            "dns-proxy max-ttl",
            value.map_or_else(|| json!({"no":true}), |ttl| json!({"max-ttl":ttl})),
        ),
        DnsChange::Route(route) => (
            "dns-proxy route object-group",
            json!({"group":route.group,"gateway":route.gateway,"interface":route.interface}),
        ),
        DnsChange::NameServer { address } => ("ip name-server", json!({"address":address})),
        DnsChange::StaticHost { domain, address } => {
            ("ip host", json!({"domain":domain,"address":address}))
        }
        DnsChange::FqdnGroup { name } => ("object-group fqdn", json!({"name":name})),
        DnsChange::FqdnDescription {
            name: _,
            description,
        } => (
            "object-group fqdn description",
            json!({"description":description}),
        ),
        DnsChange::FqdnInclude { name: _, address } => {
            ("object-group fqdn include", json!({"address":address}))
        }
        DnsChange::FqdnExclude { name: _, address } => {
            ("object-group fqdn exclude", json!({"address":address}))
        }
        DnsChange::NextDnsHost { host, token } => {
            ("nextdns assign", json!({"host":host,"token":token}))
        }
        DnsChange::NextDnsInterface { interface, token } => {
            ("nextdns assign", json!({"iface":interface,"token":token}))
        }
    };
    if let Some(fields) = body.as_object_mut() {
        fields.retain(|_key, value| !value.is_null());
    }
    (path, body)
}

/// The catalog body of a DNS-over-TLS upstream.
fn tls_body(value: &TlsUpstream) -> Value {
    json!({
        "address":value.address,
        "port":value.port,
        "fqdn":value.server_name,
        "hash":value.spki_hash,
        "interface":value.interface,
        "domain":value.domain
    })
}

/// The catalog body of a DNS-over-HTTPS upstream.
fn https_body(value: &HttpsUpstream) -> Value {
    json!({
        "url":value.url,
        "format":value.format,
        "hash":value.hash,
        "interface":value.interface,
        "domain":value.domain
    })
}

/// The CLI line of one validated DNS proxy request.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] for a path this module does not render, and
/// the refusals of the path's own renderer.
fn render_validated(validated: &ValidatedRequest) -> Result<String> {
    let value = validated.value();
    match validated.path.as_str() {
        "dns-proxy tls upstream" => render_tls(value),
        "dns-proxy https upstream" => render_https(value),
        "dns-proxy filter engine" => line_1(&validated.path, value, "engine"),
        "dns-proxy filter profile" | "object-group fqdn" => line_1(&validated.path, value, "name"),
        "dns-proxy filter profile description" => Ok(format!(
            "dns-proxy filter profile {} description {}",
            required_text(value, "name")?,
            description(value)?
        )),
        "dns-proxy filter assign host preset" => line_2(&validated.path, value, "host", "preset"),
        "dns-proxy filter assign host profile" => line_2(&validated.path, value, "host", "profile"),
        "dns-proxy filter assign interface preset" => {
            line_2(&validated.path, value, "interface", "preset")
        }
        "dns-proxy filter assign interface profile" => {
            line_2(&validated.path, value, "interface", "profile")
        }
        "dns-proxy intercept enable" => Ok(toggle_line(&validated.path, value)),
        "dns-proxy rebind-protect" => line_1(&validated.path, value, "mode"),
        "dns-proxy max-ttl" => optional_line(&validated.path, value, "max-ttl"),
        "dns-proxy route object-group" => render_route(value),
        "ip name-server" => line_1(&validated.path, value, "address"),
        "ip host" => line_2(&validated.path, value, "domain", "address"),
        "nextdns assign" => render_nextdns(value),
        _ => Err(DomainError::InvalidResponse),
    }
}

/// The `dns-proxy tls upstream` line of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a required field is missing or is not one
/// bare CLI word.
fn render_tls(value: &Value) -> Result<String> {
    let mut parts = vec![
        "dns-proxy tls upstream".to_owned(),
        required_text(value, "address")?,
    ];
    push_optional(&mut parts, value, "port", None)?;
    push_optional(&mut parts, value, "fqdn", Some("sni"))?;
    push_optional(&mut parts, value, "hash", Some("spki"))?;
    push_optional(&mut parts, value, "interface", Some("on"))?;
    push_optional(&mut parts, value, "domain", Some("domain"))?;
    Ok(parts.join(" "))
}

/// The `dns-proxy https upstream` line of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a required field is missing or is not one
/// bare CLI word.
fn render_https(value: &Value) -> Result<String> {
    let mut parts = vec![
        "dns-proxy https upstream".to_owned(),
        required_text(value, "url")?,
    ];
    push_optional(&mut parts, value, "format", None)?;
    push_optional(&mut parts, value, "hash", Some("sni"))?;
    push_optional(&mut parts, value, "interface", Some("on"))?;
    push_optional(&mut parts, value, "domain", Some("domain"))?;
    Ok(parts.join(" "))
}

/// The `dns-proxy route` line of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a required field is missing or is not one
/// bare CLI word.
fn render_route(value: &Value) -> Result<String> {
    let mut parts = vec![
        "dns-proxy route object-group".to_owned(),
        required_text(value, "group")?,
    ];
    push_optional(&mut parts, value, "gateway", None)?;
    push_optional(&mut parts, value, "interface", None)?;
    Ok(parts.join(" "))
}

/// The `nextdns` line of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a required field is missing or is not one
/// bare CLI word.
fn render_nextdns(value: &Value) -> Result<String> {
    let token = required_text(value, "token")?;
    Ok(if value.get("host").is_some() {
        format!("nextdns assign {} {token}", required_text(value, "host")?)
    } else {
        format!(
            "nextdns assign interface {} {token}",
            required_text(value, "iface")?
        )
    })
}

/// `path` followed by the required field `first` of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the field is missing or is not one bare
/// CLI word.
fn line_1(path: &str, value: &Value, first: &str) -> Result<String> {
    Ok(format!("{path} {}", required_text(value, first)?))
}

/// `path` followed by the required fields `first` and `second` of `value`.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when a field is missing or is not one bare CLI
/// word.
fn line_2(path: &str, value: &Value, first: &str, second: &str) -> Result<String> {
    Ok(format!(
        "{path} {} {}",
        required_text(value, first)?,
        required_text(value, second)?
    ))
}

/// The free-text `description` field as one quoted CLI word.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when a reply or a plan does not have the
/// expected shape ([`DomainError::InvalidResponse`]).
fn description(value: &Value) -> Result<String> {
    cli_token::quoted_text(
        value
            .get("description")
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)?,
    )
}

/// `path` with the field `field` of `value`, or `no <path>` when `value` removes it.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the field is missing or is not one bare
/// CLI word.
fn optional_line(path: &str, value: &Value, field: &str) -> Result<String> {
    if value.get("no").and_then(Value::as_bool) == Some(true) {
        Ok(format!("no {path}"))
    } else {
        line_1(path, value, field)
    }
}

/// `path`, or `no <path>` when `value` removes the setting.
fn toggle_line(path: &str, value: &Value) -> String {
    negated(value, path.to_owned())
}

/// Appends the field `key` of `value`, after `prefix` when given, when the field is set.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the field is not one bare CLI word.
fn push_optional(
    parts: &mut Vec<String>,
    value: &Value,
    key: &str,
    prefix: Option<&str>,
) -> Result<()> {
    let Some(item) = value.get(key).filter(|item| !item.is_null()) else {
        return Ok(());
    };
    if let Some(keyword) = prefix {
        parts.push(keyword.to_owned());
    }
    parts.push(value_text(item)?);
    Ok(())
}

/// The `key` field as one bare CLI token.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
fn required_text(value: &Value, key: &str) -> Result<String> {
    value_text(
        value
            .get(key)
            .filter(|item| !item.is_null())
            .ok_or(DomainError::InvalidResponse)?,
    )
}

/// A scalar as one bare CLI token; text that would split into more words is refused.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
fn value_text(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned);
    cli_token::validate(&text)?;
    Ok(text)
}

/// The catalog arguments of a DNS-over-HTTPS upstream, in CLI order.
fn render_https_args(value: &HttpsUpstream) -> Vec<Value> {
    let mut args = vec![Value::String(value.url.clone())];
    if let Some(format) = &value.format {
        args.push(Value::String(format.clone()));
    }
    if let Some(hash) = &value.hash {
        args.extend([Value::String("sni".to_owned()), Value::String(hash.clone())]);
    }
    if let Some(interface) = &value.interface {
        args.extend([
            Value::String("on".to_owned()),
            Value::String(interface.clone()),
        ]);
    }
    if let Some(domain) = &value.domain {
        args.extend([
            Value::String("domain".to_owned()),
            Value::String(domain.clone()),
        ]);
    }
    args
}

/// The router name of a DNS filter engine.
const fn engine_name(engine: FilterEngine) -> &'static str {
    match engine {
        FilterEngine::Interceptor => "interceptor",
        FilterEngine::NextDns => "nextdns",
        FilterEngine::Opkg => "opkg",
        FilterEngine::Public => "public",
        FilterEngine::SkyDns => "skydns",
    }
}

/// The router name of a rebind protection mode.
const fn rebind_name(mode: RebindProtection) -> &'static str {
    match mode {
        RebindProtection::Auto => "auto",
        RebindProtection::Strict => "strict",
    }
}
