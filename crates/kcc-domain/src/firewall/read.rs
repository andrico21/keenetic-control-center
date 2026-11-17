//! Firewall configuration and UPnP reads.

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
    model::{Direction, UpnpRedirect},
    rule_list::{ListedRule, parse_list},
};
use crate::{DomainError, Result, RouterCtx, pointer, read_show};

/// Reads named IPv4 access lists from the running configuration.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn access_lists(router: &RouterCtx) -> Result<Value> {
    let response = router.client.show_rc(json!({"access-list":{}})).await?;
    response
        .configuration_tree()
        .get("access-list")
        .cloned()
        .ok_or(DomainError::InvalidResponse)
}

/// Reads the rules of the IPv4 access list `list` from the running configuration; an
/// absent list has no rules.
///
/// Only that list is decoded, and a rule in a form the planner does not model is kept
/// unstructured (its words, no identity), so it blocks no write to its own list or to
/// another.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn configured_list(router: &RouterCtx, list: &str) -> Result<Vec<ListedRule>> {
    let lists = access_lists(router).await?;
    let object = lists.as_object().ok_or(DomainError::InvalidResponse)?;
    object.get(list).map_or_else(|| Ok(Vec::new()), parse_list)
}

/// Reads the IPv4 and IPv6 access lists with every rule's properties, and the lists applied
/// to interfaces, from the running configuration.
///
/// The configuration text is parsed and its secrets redacted before anything else reads
/// it; only lines made of plain words are kept, so no secret reaches the result.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
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
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
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
            pointer::escape(interface)
        ))
        .and_then(Value::as_array)
        .is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.get("acl").and_then(Value::as_str) == Some(acl)
                    && binding.get("direction").and_then(Value::as_str) == Some(direction.name())
            })
        }))
}

/// Reads UPnP-created redirects.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn upnp_redirects(router: &RouterCtx) -> Result<Vec<UpnpRedirect>> {
    read_show(&router.client, &["show", "upnp", "redirect"]).await
}

/// Returns whether this router catalog exposes IPv6 access lists.
#[inline]
#[must_use]
pub fn ipv6_available(router: &RouterCtx) -> bool {
    router.catalog.lookup("ipv6 access-list").is_some()
}
