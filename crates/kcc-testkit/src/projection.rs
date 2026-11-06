//! Secret-safe JSON projections of mutable CLI configuration.

mod interface;

use alloc::collections::BTreeMap;

use kcc_config::config_text::{Ast, Token, flatten};
use serde_json::{Map, Value, json};

use self::interface::interfaces;

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
        &["ip", "static"],
        command_rows(&command_lines, &["ip", "static"]),
    );
    insert_path(&mut root, &["ip", "nat"], nat_rows(&command_lines));
    insert_path(&mut root, &["dns-proxy"], dns_proxy(&command_lines));
    insert_path(&mut root, &["user"], users(&command_lines));
    insert_path(&mut root, &["service"], services(&command_lines));
    insert_path(
        &mut root,
        &["access-list"],
        grouped_rows(&command_lines, "access-list"),
    );
    insert_path(&mut root, &["interface"], interfaces(&command_lines));
    Value::Object(root)
}

/// Builds one dynamic ordinary show answer.
pub(super) fn show(ast: &Ast, path: &str, fixture: Option<&Value>) -> Option<Value> {
    let command_lines = lines(ast);
    match path {
        "ip/hotspot" => Some(hotspot(&command_lines, fixture)),
        "ip/dhcp/bindings" => Some(append_rows(fixture, dhcp_hosts(&command_lines))),
        "ip/route" => Some(append_rows(fixture, route_rows(&command_lines))),
        "dns-proxy" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            dns_proxy(&command_lines),
        )),
        "interface" => Some(overlay(
            fixture.cloned().unwrap_or_else(empty_object),
            interfaces(&command_lines),
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

/// Projects users with password hashes only.
fn users(command_lines: &[Vec<String>]) -> Value {
    let mut projected = BTreeMap::<String, Map<String, Value>>::new();
    for words in matching(command_lines, &["user"]) {
        let Some((name, fields)) = words.split_first() else {
            continue;
        };
        let user = projected.entry(name.clone()).or_insert_with(|| {
            let mut initial = Map::new();
            drop(initial.insert("name".to_owned(), Value::String(name.clone())));
            initial
        });
        match fields {
            [tag, value] if tag == "tag" => push_string(user, "tag", value),
            [password, format, digest]
                if password == "password" && matches!(format.as_str(), "md5" | "nt") =>
            {
                drop(user.insert("password".to_owned(), json!({format:digest})));
            }
            _ => {}
        }
    }
    Value::Array(projected.into_values().map(Value::Object).collect())
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
fn grouped_rows(command_lines: &[Vec<String>], prefix: &str) -> Value {
    let mut groups = Map::new();
    for words in matching(command_lines, &[prefix]) {
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

/// Projects registered hosts and hotspot overrides.
fn hotspot(command_lines: &[Vec<String>], fixture: Option<&Value>) -> Value {
    let mut rows = fixture
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let registered = matching(command_lines, &["known", "host"])
        .filter_map(|words| match words {
            [name, mac] => Some((mac.clone(), name.clone())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for (mac, name) in registered {
        let mut row = json!({"mac":mac,"name":name,"registered":true});
        if let Some(fields) = row.as_object_mut() {
            for command in matching(command_lines, &["ip", "hotspot", "host", &mac]) {
                match command {
                    [access] if matches!(access.as_str(), "permit" | "deny") => {
                        drop(fields.insert("access".to_owned(), Value::String(access.clone())));
                    }
                    [field, value] if matches!(field.as_str(), "policy" | "schedule") => {
                        drop(fields.insert(field.clone(), Value::String(value.clone())));
                    }
                    _ => {}
                }
            }
        }
        rows.retain(|candidate| candidate.get("mac").and_then(Value::as_str) != Some(&mac));
        rows.push(row);
    }
    Value::Array(rows)
}

/// Projects static routes into route-table rows.
fn route_rows(command_lines: &[Vec<String>]) -> Value {
    Value::Array(
        matching(command_lines, &["ip", "route"])
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

/// Adds a string to an array field.
fn push_string(fields: &mut Map<String, Value>, key: &str, value: &str) {
    let entry = fields
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(items) = entry {
        items.push(Value::String(value.to_owned()));
    }
}

/// Constructs an empty object value.
fn empty_object() -> Value {
    Value::Object(Map::new())
}
