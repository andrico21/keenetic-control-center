//! Client pseudonyms in MCP results and progress messages (`redact_clients_in_mcp`).

use core::{net::Ipv6Addr, ops::Range};

use kcc_app::pseudonym;
use serde_json::Value;

/// The pseudonym scope of every MCP result: one per process run.
const SCOPE: &str = "mcp";

/// Key tokens whose string value identifies a client.
const IDENTIFYING: [&str; 6] = ["mac", "hostname", "ip", "ipv4", "ipv6", "address"];

/// Members of a client object (one that has a MAC) that name the client.
const CLIENT_NAMES: [&str; 5] = ["name", "hostname", "host", "fqdn", "alias"];

/// Replaces client identifiers in `value` with keyed-hash pseudonyms: whole values under
/// identifying keys, the names inside client objects, and MAC and IP addresses found inside
/// any other string.
pub(crate) fn pseudonymize(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let client = object
                .keys()
                .any(|key| tokens(key).contains(&"mac".to_owned()));
            for (key, nested) in object {
                match nested {
                    Value::String(text) if names_client(key, client) => {
                        *text = pseudonym::client(SCOPE, text);
                    }
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Array(_)
                    | Value::Object(_) => pseudonymize(nested),
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(pseudonymize),
        Value::String(text) => *text = scrub_text(text),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `text` with every MAC, IPv4 and IPv6 address replaced by its pseudonym.
pub(crate) fn scrub_text(text: &str) -> String {
    let macs = rewrite(
        text,
        |byte| byte.is_ascii_hexdigit() || byte == b':',
        mac_in,
    );
    let v6 = rewrite(
        &macs,
        |byte| byte.is_ascii_hexdigit() || byte == b':',
        v6_in,
    );
    rewrite(&v6, |byte| byte.is_ascii_digit() || byte == b'.', v4_in)
}

/// Whether the string under `key` names a client.
fn names_client(key: &str, client_object: bool) -> bool {
    let tokens = tokens(key);
    let has = |wanted: &str| tokens.iter().any(|token| token == wanted);
    IDENTIFYING.iter().any(|wanted| has(wanted))
        || tokens
            .windows(2)
            .any(|pair| matches!(pair, [host, name] if host == "host" && name == "name"))
        || (client_object && CLIENT_NAMES.iter().any(|wanted| has(wanted)))
}

/// The lowercase words of `key`, split on non-alphanumerics and camelCase boundaries.
fn tokens(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for character in key.chars() {
        let boundary = !character.is_alphanumeric() || (previous_lower && character.is_uppercase());
        if boundary && !word.is_empty() {
            words.push(core::mem::take(&mut word));
        }
        if character.is_alphanumeric() {
            word.extend(character.to_lowercase());
        }
        previous_lower = character.is_lowercase() || character.is_ascii_digit();
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// Replaces the part of every maximal run of `in_run` bytes that `locate` accepts.
fn rewrite(text: &str, in_run: fn(u8) -> bool, locate: fn(&str) -> Option<Range<usize>>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut start = None;
    for (index, byte) in text.bytes().chain(core::iter::once(0)).enumerate() {
        match (start, in_run(byte)) {
            (None, true) => start = Some(index),
            (Some(first), false) => {
                start = None;
                let found = text
                    .get(first..index)
                    .and_then(|run| locate(run).map(|range| (run, range)));
                if let Some((run, range)) = found
                    && let (Some(kept), Some(address)) = (
                        text.get(copied..first.saturating_add(range.start)),
                        run.get(range.clone()),
                    )
                {
                    out.push_str(kept);
                    out.push_str(&pseudonym::client(SCOPE, address));
                    copied = first
                        .saturating_add(range.start)
                        .saturating_add(address.len());
                }
            }
            (Some(_) | None, _) => {}
        }
    }
    out.push_str(text.get(copied..).unwrap_or_default());
    out
}

/// The `hh:hh:hh:hh:hh:hh` MAC inside a run of hex digits and colons.
fn mac_in(run: &str) -> Option<Range<usize>> {
    let bytes = run.as_bytes();
    bytes.windows(17).enumerate().find_map(|(start, window)| {
        let shaped = window.chunks(3).all(|group| match *group {
            [high, low, separator] => {
                high.is_ascii_hexdigit() && low.is_ascii_hexdigit() && separator == b':'
            }
            [high, low] => high.is_ascii_hexdigit() && low.is_ascii_hexdigit(),
            _ => false,
        });
        let end = start.saturating_add(17);
        let starts_group = start == 0
            || start
                .checked_sub(1)
                .is_some_and(|before| bytes.get(before) == Some(&b':'));
        let ends_group = match bytes.get(end) {
            None => true,
            Some(&byte) => byte == b':' && bytes.len() == end.saturating_add(1),
        };
        (shaped && starts_group && ends_group).then_some(start..end)
    })
}

/// The IPv6 address that makes up a run of hex digits and colons, less a stray single colon
/// at either end.
fn v6_in(run: &str) -> Option<Range<usize>> {
    let lead = usize::from(run.starts_with(':') && !run.starts_with("::"));
    let trail = usize::from(run.ends_with(':') && !run.ends_with("::"));
    let end = run.len().saturating_sub(trail);
    let core = run.get(lead..end)?;
    (core.matches(':').count() >= 2 && core.parse::<Ipv6Addr>().is_ok()).then_some(lead..end)
}

/// The dotted-quad IPv4 address that makes up a run of digits and dots, less stray dots.
fn v4_in(run: &str) -> Option<Range<usize>> {
    let lead = run.len().saturating_sub(run.trim_start_matches('.').len());
    let core = run.trim_matches('.');
    let parts: Vec<&str> = core.split('.').collect();
    (parts.len() == 4
        && parts
            .iter()
            .all(|part| (1..=3).contains(&part.len()) && part.parse::<u8>().is_ok()))
    .then(|| lead..lead.saturating_add(core.len()))
}
