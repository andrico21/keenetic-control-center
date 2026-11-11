//! Shared fail-closed classification of firewall changes affecting management traffic.

use alloc::collections::BTreeSet;
use core::str;

use kcc_catalog::Risk;
use kcc_config::{
    config_text::{Token, flatten, parse},
    secrets::redact,
};
use kcc_rci::{ConfigKind, ObjectName};
use secrecy::ExposeSecret as _;

use crate::{DomainError, Result, RouterCtx, interfaces};

/// Classifies the interfaces whose traffic a firewall change affects.
///
/// Failed detection is management risk; successful unknown verdicts retain the
/// interface classifier's conservative management-bridge fallback.
// cancel-safe: topology reads do not change router state.
#[inline]
pub async fn interfaces_risk(router: &RouterCtx, names: &[String]) -> Risk {
    if names.is_empty() {
        return Risk::Write;
    }
    match configuration_lines(router).await {
        Ok(lines) => classify(router, names, &lines).await,
        Err(_error) => Risk::Management,
    }
}

/// Includes parent bridges because filtering a member also filters bridge access.
// cancel-safe: topology reads do not change router state.
async fn classify(router: &RouterCtx, names: &[String], lines: &[Vec<String>]) -> Risk {
    let mut highest = Risk::Write;
    let mut distinct = names.iter().cloned().collect::<BTreeSet<_>>();
    loop {
        let before = distinct.len();
        for line in lines {
            if let [interface, bridge, include, member] = line.as_slice()
                && interface == "interface"
                && include == "include"
                && distinct.contains(member)
            {
                let _: bool = distinct.insert(bridge.clone());
            }
        }
        if distinct.len() == before {
            break;
        }
    }
    for name in distinct {
        let found = match ObjectName::try_from(name) {
            Ok(object) => interfaces::detect_management(router, &object)
                .await
                .map_or(Risk::Management, |verdict| verdict.risk(&object)),
            Err(_error) => Risk::Management,
        };
        highest = highest.max(found);
    }
    highest
}

/// Classifies every interface currently carrying a list, failing closed on unreadable bindings.
// cancel-safe: configuration and topology reads do not change router state.
pub(super) async fn list_risk(router: &RouterCtx, list: &str) -> Risk {
    let lines = match configuration_lines(router).await {
        Ok(lines) => lines,
        Err(_error) => return Risk::Management,
    };
    let mut names = Vec::new();
    for words in &lines {
        if let [interface, name, ip, group, acl, _direction] = words.as_slice()
            && interface == "interface"
            && ip == "ip"
            && group == "access-group"
            && acl == list
        {
            names.push(name.clone());
        }
    }
    classify(router, &names, &lines).await
}

/// Reads redacted topology and binding lines from one running-configuration snapshot.
// cancel-safe: a single read changes nothing on the router.
async fn configuration_lines(router: &RouterCtx) -> Result<Vec<Vec<String>>> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    let text =
        str::from_utf8(bytes.expose_secret()).map_err(|_error| DomainError::InvalidResponse)?;
    let ast = parse(text).map_err(|_error| DomainError::InvalidResponse)?;
    let mut lines = Vec::new();
    for line in flatten(&redact(&ast)) {
        let words = line
            .tokens
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some(word.clone()),
                Token::Ns3(_) | _ => None,
            })
            .collect::<Vec<_>>();
        lines.push(words);
    }
    Ok(lines)
}
