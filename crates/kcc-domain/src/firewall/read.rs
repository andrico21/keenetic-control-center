//! Firewall configuration and UPnP reads.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "router reads are not inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private access-list decoders are narrowly named"
    )
)]

use alloc::collections::BTreeMap;
use core::str;

use kcc_config::{
    config_text::{CliLine, Token, flatten, parse},
    secrets::redact,
};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

use super::{
    lists::Firewall,
    model::{Action, ConfiguredRule, Direction, Protocol, Rule, UpnpRedirect},
};
use crate::{DomainError, Result, RouterCtx, read_show};

/// Reads named IPv4 access lists from the running configuration.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn access_lists(router: &RouterCtx) -> Result<Value> {
    let response = router.client.show_rc(json!({"access-list":{}})).await?;
    response
        .configuration_tree()
        .get("access-list")
        .cloned()
        .ok_or(DomainError::InvalidResponse)
}

/// Reads typed IPv4 access-list rules from the running configuration.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn configured_rules(router: &RouterCtx) -> Result<BTreeMap<String, Vec<ConfiguredRule>>> {
    let lists = access_lists(router).await?;
    let object = lists.as_object().ok_or(DomainError::InvalidResponse)?;
    object
        .iter()
        .map(|(name, rows)| Ok((name.clone(), parse_list(rows)?)))
        .collect()
}

/// Reads the IPv4 and IPv6 access lists with every rule's properties, and the lists applied
/// to interfaces, from the running configuration.
///
/// The configuration text is parsed and its secrets redacted before anything else reads
/// it; only lines made of plain words are kept, so no secret reaches the result.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn firewall(router: &RouterCtx) -> Result<Firewall> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    let text =
        str::from_utf8(bytes.expose_secret()).map_err(|_error| DomainError::InvalidResponse)?;
    let ast = parse(text).map_err(|_error| DomainError::InvalidResponse)?;
    let lines: Vec<Vec<String>> = flatten(&redact(&ast))
        .iter()
        .filter_map(plain_words)
        .collect();
    Ok(Firewall::from_lines(&lines))
}

/// The words of a configuration line made of plain words only.
fn plain_words(line: &CliLine) -> Option<Vec<String>> {
    line.tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => Some(word.clone()),
            Token::Ns3(_) | _ => None,
        })
        .collect()
}

/// Reads whether one interface carries the named access list in the requested direction.
pub(crate) async fn has_binding(
    router: &RouterCtx,
    interface: &str,
    acl: &str,
    direction: Direction,
) -> Result<bool> {
    let response = router
        .client
        .show_rc(json!({"interface":{interface:{"ip":{"access-group":{}}}}}))
        .await?;
    Ok(response
        .configuration_tree()
        .pointer(&format!(
            "/interface/{}/ip/access-group",
            interface.replace('~', "~0").replace('/', "~1")
        ))
        .and_then(Value::as_array)
        .is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.get("acl").and_then(Value::as_str) == Some(acl)
                    && binding.get("direction").and_then(Value::as_str) == Some(direction.name())
            })
        }))
}

fn parse_list(value: &Value) -> Result<Vec<ConfiguredRule>> {
    let rows = value.as_array().ok_or(DomainError::InvalidResponse)?;
    let mut rules = Vec::new();
    let mut properties = Vec::new();
    for row in rows {
        let command = row
            .get("command")
            .and_then(Value::as_array)
            .ok_or(DomainError::InvalidResponse)?
            .iter()
            .map(|word| {
                word.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or(DomainError::InvalidResponse)
            })
            .collect::<Result<Vec<_>>>()?;
        if command.is_empty() {
            continue;
        }
        if command.first().is_some_and(|word| word == "rule") {
            properties.push(command);
        } else {
            rules.push(command);
        }
    }
    rules
        .into_iter()
        .enumerate()
        .map(|(index, words)| configured_rule(index, &words, &properties))
        .collect()
}

fn configured_rule(
    index: usize,
    command: &[String],
    properties: &[Vec<String>],
) -> Result<ConfiguredRule> {
    let parsed_rule = parse_rule(command)?;
    let number = index.to_string();
    let property = |name: &str| {
        properties.iter().find_map(|line| match line.as_slice() {
            [keyword, at, found, value] if keyword == "rule" && at == &number && found == name => {
                Some(value.clone())
            }
            _ => None,
        })
    };
    Ok(ConfiguredRule {
        rule: parsed_rule,
        index,
        disabled: properties.iter().any(|line| {
            matches!(line.as_slice(), [keyword, at, field] if keyword == "rule" && at == &number && field == "disable")
        }),
        schedule: property("schedule"),
        description: property("description"),
    })
}

fn parse_rule(words: &[String]) -> Result<Rule> {
    let [action_word, protocol_word, rest @ ..] = words else {
        return Err(DomainError::InvalidResponse);
    };
    let action = match action_word.as_str() {
        "permit" => Action::Permit,
        "deny" => Action::Deny,
        _ => return Err(DomainError::InvalidResponse),
    };
    let protocol = match protocol_word.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "esp" => Protocol::Esp,
        "gre" => Protocol::Gre,
        "ipip" => Protocol::IpIp,
        "ip" => Protocol::Ip,
        _ => return Err(DomainError::InvalidResponse),
    };
    let (source, source_mask, source_port, source_end_port, destination_words) = side(rest)?;
    let (destination, destination_mask, destination_port, destination_end_port, tail) =
        side(destination_words)?;
    if !tail.is_empty() {
        return Err(DomainError::InvalidResponse);
    }
    Ok(Rule {
        action,
        protocol,
        source,
        source_mask,
        destination,
        destination_mask,
        source_port,
        source_end_port,
        destination_port,
        destination_end_port,
    })
}

type ParsedSide<'words> = (String, String, Option<u16>, Option<u16>, &'words [String]);

fn side(words: &[String]) -> Result<ParsedSide<'_>> {
    let [address, mask, rest @ ..] = words else {
        return Err(DomainError::InvalidResponse);
    };
    let (port, end, tail) = match rest {
        [keyword, operator, value, tail @ ..] if keyword == "port" && operator == "eq" => {
            (Some(port(value)?), None, tail)
        }
        [keyword, range, start, end, tail @ ..] if keyword == "port" && range == "range" => {
            (Some(port(start)?), Some(port(end)?), tail)
        }
        [keyword, ..] if keyword == "port" => return Err(DomainError::InvalidResponse),
        _ => (None, None, rest),
    };
    Ok((address.clone(), mask.clone(), port, end, tail))
}

fn port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_error| DomainError::InvalidResponse)
}

/// Reads UPnP-created redirects.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn upnp_redirects(router: &RouterCtx) -> Result<Vec<UpnpRedirect>> {
    read_show(&router.client, &["show", "upnp", "redirect"]).await
}

/// Returns whether this router catalog exposes IPv6 access lists.
#[inline]
#[must_use]
pub fn ipv6_available(router: &RouterCtx) -> bool {
    router.catalog.lookup("ipv6 access-list").is_some()
}
