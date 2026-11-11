//! The connection policies of the policies view.
//!
//! The router's `show ip policy` answer and the configured `ip policy` lines of `show rc`
//! are joined by name, each policy with its permitted interfaces in order and multipath.

use core::fmt::Display;

use kcc_domain::{
    DomainError, RouterCtx,
    policies::{model::PolicyState, read},
};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::{ConfigKind, RciBody};
use serde_json::{Value, json};

use super::route_rows::text_key;
use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// One interface a policy may use, and its order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Permit {
    /// The interface.
    interface: String,
    /// Its order; lower first.
    order: Option<u32>,
}

impl Permit {
    /// The interface.
    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    /// Its order.
    pub(crate) const fn order(&self) -> Option<u32> {
        self.order
    }
}

/// One connection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Policy {
    /// Policy name.
    name: String,
    /// Description.
    description: Option<String>,
    /// Permitted interfaces, lowest order first.
    permits: Vec<Permit>,
    /// Whether multipath is on.
    multipath: bool,
}

impl Policy {
    /// Policy name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Description.
    pub(crate) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Permitted interfaces, lowest order first.
    pub(crate) fn permits(&self) -> &[Permit] {
        &self.permits
    }

    /// Whether multipath is on.
    pub(crate) const fn multipath(&self) -> bool {
        self.multipath
    }

    /// The order of `interface` in the policy, when it is permitted.
    pub(crate) fn permit(&self, interface: &str) -> Option<&Permit> {
        self.permits
            .iter()
            .find(|permit| permit.interface == interface)
    }

    /// The policy `name` from its runtime state and configured `lines`.
    fn joined(name: String, state: Option<&PolicyState>, lines: &[Vec<String>]) -> Self {
        let configured = lines.iter().find_map(|words| match words.as_slice() {
            [keyword, text] if keyword == "description" => Some(text.clone()),
            _ => None,
        });
        let mut permits: Vec<Permit> = lines
            .iter()
            .filter_map(|words| match words.as_slice() {
                [permit, global, interface, rest @ ..]
                    if permit == "permit" && global == "global" =>
                {
                    let order = match rest {
                        [keyword, number] if keyword == "order" => number.parse().ok(),
                        _ => None,
                    };
                    Some(Permit {
                        interface: interface.clone(),
                        order,
                    })
                }
                _ => None,
            })
            .collect();
        permits.sort_by_key(|permit| permit.order.unwrap_or(u32::MAX));
        Self {
            description: configured.or_else(|| state?.description.clone()),
            multipath: lines.iter().any(|words| words == &["multipath"])
                || state.is_some_and(|found| found.multipath == Some(true)),
            permits,
            name,
        }
    }
}

impl Row for Policy {
    const COLUMNS: &'static [&'static str] = &["name", "description", "multipath"];

    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "description" => text_key(self.description()),
            "multipath" => SortKey::Number(i128::from(self.multipath)),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
            || self
                .description()
                .is_some_and(|text| text.to_lowercase().contains(needle))
            || self
                .permits
                .iter()
                .any(|permit| permit.interface.to_lowercase().contains(needle))
    }
}

/// The router's connection policies, by name.
///
/// # Errors
///
/// Returns why the router did not answer.
// cancel-safe: reads only.
pub(crate) async fn read_policies(domain: &RouterCtx) -> Result<Vec<Policy>, MessageKey> {
    let unreachable = |error: &dyn Display| {
        tracing::warn!(%error, "routing page: policies unavailable");
        keys::WEB_KIT_UNREACHABLE
    };
    let states = read::policies(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    let configured = configured(domain)
        .await
        .map_err(|error| unreachable(&error))?;
    let mut names: Vec<String> = states
        .iter()
        .filter_map(|state| state.name.clone())
        .chain(configured.iter().map(|(name, _)| name.clone()))
        .collect();
    names.sort();
    names.dedup();
    Ok(names
        .into_iter()
        .map(|name| {
            let state = states
                .iter()
                .find(|found| found.name.as_deref() == Some(name.as_str()));
            let lines = configured
                .iter()
                .find(|(found, _)| *found == name)
                .map_or(&[][..], |(_, lines)| lines.as_slice());
            Policy::joined(name, state, lines)
        })
        .collect())
}

/// The configured lines of every policy, from `show rc ip policy`.
///
/// # Errors
///
/// Returns the router error, or the domain's invalid-response error for another shape.
// cancel-safe: reads only.
pub(crate) async fn configured(
    domain: &RouterCtx,
) -> Result<Vec<(String, Vec<Vec<String>>)>, DomainError> {
    let RciBody::Json(response) = domain.client.show_rc(json!({"ip": {"policy": {}}})).await?
    else {
        return Err(DomainError::InvalidResponse);
    };
    let Some(Value::Object(policies)) = response
        .configuration_tree(ConfigKind::Running)
        .and_then(|tree| tree.pointer("/ip/policy"))
    else {
        return Ok(Vec::new());
    };
    Ok(policies
        .iter()
        .map(|(name, rows)| (name.clone(), words(rows)))
        .collect())
}

/// The command words of the configured rows `rows`: arrays of words or `{command}`.
fn words(rows: &Value) -> Vec<Vec<String>> {
    let text = |list: &Vec<Value>| -> Vec<String> {
        list.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    rows.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|row| match row {
                    Value::Array(found) => Some(text(found)),
                    Value::Object(fields) => {
                        fields.get("command").and_then(Value::as_array).map(text)
                    }
                    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}
