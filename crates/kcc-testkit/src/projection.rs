//! Secret-safe JSON projections of mutable CLI configuration.

mod hosts;
mod hotspot_policy;
mod interface;
mod management;
mod ntp;
mod remote;
mod schedule;
mod system;
mod vpn_server;

use kcc_config::config_text::{Ast, Token, flatten};
use serde_json::{Map, Value, json};

use self::{
    hosts::{hotspot, users},
    interface::interfaces,
    system::{clock_show, system, system_show},
};

/// Builds mutable `show rc` or `show sc` fields.
pub(super) fn configuration(ast: &Ast) -> Value {
    let command_lines = lines(ast);
    let mut root = Map::new();
    insert_path(
        &mut root,
        &["ip", "dhcp", "host"],
        dhcp_hosts(&command_lines),
    );
    insert_path(
        &mut root,
        &["ip", "route"],
        command_rows(&command_lines, &["ip", "route"]),
    );
    insert_path(
        &mut root,
        &["ipv6", "route"],
        command_rows(&command_lines, &["ipv6", "route"]),
    );
    insert_path(
        &mut root,
        &["ip", "static"],
        command_rows(&command_lines, &["ip", "static"]),
    );
    insert_path(&mut root, &["ip", "nat"], nat_rows(&command_lines));
    insert_path(
        &mut root,
        &["ip", "policy"],
        grouped_rows(&command_lines, &["ip", "policy"]),
    );
    insert_path(&mut root, &["dns-proxy"], dns_proxy(&command_lines));
    insert_path(&mut root, &["user"], users(&command_lines));
    insert_path(&mut root, &["service"], services(&command_lines));
    insert_path(&mut root, &["system"], system(&command_lines));
    insert_path(
        &mut root,
        &["access-list"],
        grouped_rows(&command_lines, &["access-list"]),
    );
    insert_path(&mut root, &["interface"], interfaces(&command_lines));
    management::extend(&mut root, &command_lines);
    remote::extend(&mut root, &command_lines);
    vpn_server::extend(&mut root, &command_lines);
    insert_path(&mut root, &["ntp"], ntp::project(&command_lines));
    insert_path(&mut root, &["schedule"], schedule::rows(&command_lines));
    insert_path(
        &mut root,
        &["ip", "hotspot"],
        hotspot_policy::project(&command_lines),
    );
    Value::Object(root)
}

/// Builds one dynamic ordinary show answer.
pub(super) fn show(ast: &Ast, path: &str, fixture: Option<&Value>) -> Option<Value> {
    let command_lines = lines(ast);
    match path {
        "mws/member" => Some(append_rows(
            fixture,
            Value::Array(
                matching(&command_lines, &["mws", "acquire"])
                    .filter_map(|words| words.first())
                    .map(|candidate| json!({"id":candidate,"online":true}))
                    .collect(),
            ),
        )),
        "schedule" => Some(append_rows(fixture, schedule::rows(&command_lines))),
        "ip/hotspot" => Some(hotspot(&command_lines, fixture)),
        "ip/dhcp/bindings" => Some(append_rows(fixture, dhcp_hosts(&command_lines))),
        "ip/route" => Some(append_rows(fixture, route_rows(&command_lines))),
        "ipv6/route" => Some(append_rows(
            fixture,
            route_rows_for(&command_lines, &["ipv6", "route"]),
        )),
        "dns-proxy" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            dns_proxy(&command_lines),
        )),
        "interface" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            interfaces(&command_lines),
        )),
        "system" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            system_show(&command_lines),
        )),
        "clock/date" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            clock_show(&command_lines),
        )),
        _ => None,
    }
}

/// Flattens an AST while replacing NS3 payloads with presence markers.
fn lines(ast: &Ast) -> Vec<Vec<String>> {
    flatten(ast)
        .into_iter()
        .map(|line| {
            line.tokens
                .into_iter()
                .flat_map(|token| match token {
                    Token::Word(word) => vec![word],
                    Token::Ns3(_) => vec!["ns3".to_owned()],
                    _ => Vec::new(),
                })
                .collect()
        })
        .collect()
}

/// Projects static leases.
fn dhcp_hosts(command_lines: &[Vec<String>]) -> Value {
    Value::Array(
        matching(command_lines, &["ip", "dhcp", "host"])
            .filter_map(|words| match words {
                [mac, address] => Some(json!({"mac":mac,"address":address})),
                _ => None,
            })
            .collect(),
    )
}

/// Projects encrypted DNS upstreams.
fn dns_proxy(command_lines: &[Vec<String>]) -> Value {
    let mut proxy = Map::new();
    for kind in ["tls", "https"] {
        let upstreams = matching(command_lines, &["dns-proxy", kind, "upstream"])
            .map(|words| Value::Array(words.iter().cloned().map(Value::String).collect()))
            .collect();
        drop(proxy.insert(kind.to_owned(), json!({"upstream":Value::Array(upstreams)})));
    }
    Value::Object(proxy)
}

/// Projects enabled services.
fn services(command_lines: &[Vec<String>]) -> Value {
    Value::Array(
        matching(command_lines, &["service"])
            .filter_map(|words| words.first())
            .map(|name| json!({"name":name,"enabled":true}))
            .collect(),
    )
}

/// Projects NAT interface declarations.
fn nat_rows(command_lines: &[Vec<String>]) -> Value {
    Value::Array(
        matching(command_lines, &["ip", "nat"])
            .filter_map(|words| words.first())
            .map(|name| json!({"interface":name}))
            .collect(),
    )
}

/// Projects named command contexts.
fn grouped_rows(command_lines: &[Vec<String>], prefix: &[&str]) -> Value {
    let mut groups = Map::new();
    for words in matching(command_lines, prefix) {
        let Some((name, command)) = words.split_first() else {
            continue;
        };
        let entry = groups
            .entry(name.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(rows) = entry {
            rows.push(json!({"command":command}));
        }
    }
    Value::Object(groups)
}

/// Projects static routes into route-table rows.
fn route_rows(command_lines: &[Vec<String>]) -> Value {
    route_rows_for(command_lines, &["ip", "route"])
}

/// Projects one static route family into routing-table rows.
fn route_rows_for(command_lines: &[Vec<String>], prefix: &[&str]) -> Value {
    Value::Array(
        matching(command_lines, prefix)
            .map(|words| json!({"static":true,"command":words}))
            .collect(),
    )
}

/// Projects command tails under one prefix.
fn command_rows(command_lines: &[Vec<String>], prefix: &[&str]) -> Value {
    Value::Array(
        matching(command_lines, prefix)
            .map(|words| json!({"command":words}))
            .collect(),
    )
}

/// Iterates command tails matching a literal prefix.
pub(super) fn matching<'lines>(
    command_lines: &'lines [Vec<String>],
    prefix: &'lines [&str],
) -> impl Iterator<Item = &'lines [String]> + 'lines {
    command_lines.iter().filter_map(move |line| {
        let matched = line
            .iter()
            .map(String::as_str)
            .zip(prefix.iter().copied())
            .all(|(word, expected)| word == expected)
            && line.len() >= prefix.len();
        matched.then(|| line.get(prefix.len()..)).flatten()
    })
}

/// Inserts a value beneath an object path.
fn insert_path(root: &mut Map<String, Value>, path: &[&str], value: Value) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        drop(root.insert((*first).to_owned(), value));
        return;
    }
    let entry = root.entry((*first).to_owned()).or_insert_with(empty_object);
    if let Value::Object(object) = entry {
        insert_path(object, rest, value);
    }
}

/// Recursively overlays dynamic fields onto fixture fields.
fn overlay(mut fixture: Value, dynamic: Value) -> Value {
    match (&mut fixture, dynamic) {
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                let merged = match target.remove(&key) {
                    Some(old) => overlay(old, value),
                    None => value,
                };
                drop(target.insert(key, merged));
            }
            fixture
        }
        (_, replacement) => replacement,
    }
}

/// Appends dynamic rows to fixture rows.
fn append_rows(fixture: Option<&Value>, dynamic: Value) -> Value {
    let mut rows = fixture
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Value::Array(mut additions) = dynamic {
        rows.append(&mut additions);
    }
    Value::Array(rows)
}

/// Constructs an empty object value.
fn empty_object() -> Value {
    Value::Object(Map::new())
}
