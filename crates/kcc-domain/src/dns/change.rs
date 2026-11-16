//! Catalog validation and protected workflow conversion for DNS changes.
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private render helpers are named after the catalog fields they transform"
    )
)]

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Value, json};

use super::{DnsChange, FilterEngine, HttpsUpstream, RebindProtection, TlsUpstream};
use crate::{ChangeOp, DomainError, Result, RouterCtx, verification};

/// Validates a typed DNS change against the selected router catalog.
pub(super) fn plan(router: &RouterCtx, change: &DnsChange) -> Result<ChangeOp> {
    let (path, body) = catalog_input(change);
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, &body)
        .map_err(|issues| DomainError::Validation { issues })?;
    let line = if let DnsChange::FqdnInclude { name, address } = change {
        format!("object-group fqdn {name} include {address}")
    } else if let DnsChange::FqdnExclude { name, address } = change {
        format!("object-group fqdn {name} exclude {address}")
    } else {
        render_validated(&validated)?
    };
    let command = ValidatedCli::new(line, validated);
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
pub(super) fn request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let commands = if operation.commands.is_empty() {
        operation
            .requests
            .iter()
            .map(|validated| {
                Ok(ValidatedCli::new(
                    render_validated(validated)?,
                    validated.clone(),
                ))
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
        DnsChange::FqdnDescription { name, description } => (
            "object-group fqdn description",
            json!({"name":name,"description":description}),
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

fn https_body(value: &HttpsUpstream) -> Value {
    json!({
        "url":value.url,
        "format":value.format,
        "hash":value.hash,
        "interface":value.interface,
        "domain":value.domain
    })
}

fn render_validated(validated: &ValidatedRequest) -> Result<String> {
    let value = validated.value();
    match validated.path.as_str() {
        "dns-proxy tls upstream" => Ok(render_tls(value)),
        "dns-proxy https upstream" => Ok(render_https(value)),
        "dns-proxy filter engine" => line_1(&validated.path, value, "engine"),
        "dns-proxy filter profile" | "object-group fqdn" => line_1(&validated.path, value, "name"),
        "dns-proxy filter profile description" => {
            line_2(&validated.path, value, "name", "description")
        }
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
        "dns-proxy route object-group" => Ok(render_route(value)),
        "ip name-server" => line_1(&validated.path, value, "address"),
        "ip host" => line_2(&validated.path, value, "domain", "address"),
        "object-group fqdn description" => contextual_line(value),
        "nextdns assign" => Ok(render_nextdns(value)),
        _ => Err(DomainError::InvalidResponse),
    }
}

fn render_tls(value: &Value) -> String {
    let mut parts = vec!["dns-proxy tls upstream".to_owned(), text(value, "address")];
    push_optional(&mut parts, value, "port", None);
    push_optional(&mut parts, value, "fqdn", Some("sni"));
    push_optional(&mut parts, value, "hash", Some("spki"));
    push_optional(&mut parts, value, "interface", Some("on"));
    push_optional(&mut parts, value, "domain", Some("domain"));
    parts.join(" ")
}

fn render_https(value: &Value) -> String {
    let mut parts = vec!["dns-proxy https upstream".to_owned(), text(value, "url")];
    push_optional(&mut parts, value, "format", None);
    push_optional(&mut parts, value, "hash", Some("sni"));
    push_optional(&mut parts, value, "interface", Some("on"));
    push_optional(&mut parts, value, "domain", Some("domain"));
    parts.join(" ")
}

fn render_route(value: &Value) -> String {
    let mut parts = vec![
        "dns-proxy route object-group".to_owned(),
        text(value, "group"),
    ];
    push_optional(&mut parts, value, "gateway", None);
    push_optional(&mut parts, value, "interface", None);
    parts.join(" ")
}

fn render_nextdns(value: &Value) -> String {
    value.get("host").and_then(Value::as_str).map_or_else(
        || {
            format!(
                "nextdns assign interface {} {}",
                text(value, "iface"),
                text(value, "token")
            )
        },
        |host| format!("nextdns assign {host} {}", text(value, "token")),
    )
}

fn line_1(path: &str, value: &Value, first: &str) -> Result<String> {
    Ok(format!("{path} {}", required_text(value, first)?))
}

fn line_2(path: &str, value: &Value, first: &str, second: &str) -> Result<String> {
    Ok(format!(
        "{path} {} {}",
        required_text(value, first)?,
        required_text(value, second)?
    ))
}

fn contextual_line(value: &Value) -> Result<String> {
    Ok(format!(
        "object-group fqdn {} description {}",
        required_text(value, "name")?,
        required_text(value, "description")?
    ))
}

fn optional_line(path: &str, value: &Value, field: &str) -> Result<String> {
    if value.get("no").and_then(Value::as_bool) == Some(true) {
        Ok(format!("no {path}"))
    } else {
        line_1(path, value, field)
    }
}

fn toggle_line(path: &str, value: &Value) -> String {
    if value.get("no").and_then(Value::as_bool) == Some(true) {
        format!("no {path}")
    } else {
        path.to_owned()
    }
}

fn push_optional(parts: &mut Vec<String>, value: &Value, key: &str, prefix: Option<&str>) {
    let Some(item) = value.get(key).filter(|item| !item.is_null()) else {
        return;
    };
    if let Some(keyword) = prefix {
        parts.push(keyword.to_owned());
    }
    parts.push(value_text(item));
}

fn required_text(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .filter(|item| !item.is_null())
        .map(value_text)
        .ok_or(DomainError::InvalidResponse)
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).map_or_else(String::new, value_text)
}

fn value_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

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

const fn engine_name(engine: FilterEngine) -> &'static str {
    match engine {
        FilterEngine::Interceptor => "interceptor",
        FilterEngine::NextDns => "nextdns",
        FilterEngine::Opkg => "opkg",
        FilterEngine::Public => "public",
        FilterEngine::SkyDns => "skydns",
    }
}

const fn rebind_name(mode: RebindProtection) -> &'static str {
    match mode {
        RebindProtection::Auto => "auto",
        RebindProtection::Strict => "strict",
    }
}
