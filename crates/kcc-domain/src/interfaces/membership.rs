//! Shared bridge membership from configuration text and the show-rc tree.

use alloc::collections::{BTreeMap, BTreeSet};
use core::str;

use kcc_config::{
    config_text::{Token, flatten, parse},
    secrets::redact,
};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{DomainError, Result, RouterCtx};

/// Union of every reported include and inherit edge, indexed by bridge.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, configuration reads do not change router state.
pub(crate) async fn read(router: &RouterCtx) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let lines = configuration_lines(router).await?;
    let response = router.client.show_rc(json!({"interface":{}})).await?;
    let tree = response
        .configuration_tree()
        .get("interface")
        .ok_or(DomainError::InvalidResponse)?;
    merge(lines, tree)
}

/// Parses and unions the two independently reported membership representations.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
fn merge(lines: Vec<Vec<String>>, tree: &Value) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let interfaces: BTreeMap<String, Members> =
        serde_json::from_value(tree.clone()).map_err(|_error| DomainError::InvalidResponse)?;
    let mut membership = BTreeMap::<String, BTreeSet<String>>::new();
    for (bridge, members) in interfaces {
        membership.entry(bridge).or_default().extend(
            members
                .include
                .into_iter()
                .chain(members.inherit)
                .map(|member| member.interface),
        );
    }
    for words in lines {
        if let [interface, bridge, keyword, member] = words.as_slice()
            && interface == "interface"
            && matches!(keyword.as_str(), "include" | "inherit")
        {
            let _: bool = membership
                .entry(bridge.clone())
                .or_default()
                .insert(member.clone());
        }
    }
    Ok(membership)
}

/// Reads redacted topology and binding lines from a running-configuration snapshot.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read changes nothing on the router.
pub(crate) async fn configuration_lines(router: &RouterCtx) -> Result<Vec<Vec<String>>> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    let text =
        str::from_utf8(bytes.expose_secret()).map_err(|_error| DomainError::InvalidResponse)?;
    let ast = parse(text).map_err(|_error| DomainError::InvalidResponse)?;
    Ok(flatten(&redact(&ast))
        .into_iter()
        .map(|line| {
            line.tokens
                .into_iter()
                .filter_map(|token| match token {
                    Token::Word(word) => Some(word),
                    Token::Ns3(_) | _ => None,
                })
                .collect()
        })
        .collect())
}

/// Typed membership fields; unrelated interface settings are ignored.
#[derive(Deserialize)]
struct Members {
    /// Explicit bridge members.
    #[serde(default)]
    include: Vec<Member>,
    /// Inherited bridge members.
    #[serde(default)]
    inherit: Vec<Member>,
}

/// A member must name its interface; malformed evidence cannot silently disappear.
#[derive(Deserialize)]
struct Member {
    /// Interface identifier returned by the router.
    interface: String,
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions report membership contract failures"
)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use super::merge;
    use crate::DomainError;

    /// Either keyword from either source contributes its distinct member without replacement.
    #[test]
    fn membership_union_preserves_each_source_and_keyword() {
        let lines = ["include", "inherit"]
            .map(|keyword| {
                ["interface", "Bridge0", keyword, keyword]
                    .map(str::to_owned)
                    .to_vec()
            })
            .to_vec();
        let tree = json!({"Bridge0":{"include":[{"interface":"show-include"}],"inherit":[{"interface":"show-inherit"}]}});
        let expected = BTreeMap::from([(
            "Bridge0".to_owned(),
            BTreeSet::from([
                "include".to_owned(),
                "inherit".to_owned(),
                "show-include".to_owned(),
                "show-inherit".to_owned(),
            ]),
        )]);
        assert_eq!(merge(lines, &tree).ok(), Some(expected));
    }

    /// Invalid membership payloads cannot be treated as an empty successful topology read.
    #[test]
    fn malformed_membership_is_refused() {
        for tree in [
            json!({"Bridge0":{"include":"invalid"}}),
            json!({"Bridge0":{"inherit":[{}]}}),
        ] {
            assert!(matches!(
                merge(Vec::new(), &tree),
                Err(DomainError::InvalidResponse)
            ));
        }
    }
}
