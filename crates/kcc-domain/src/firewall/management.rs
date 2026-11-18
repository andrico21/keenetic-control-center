//! Shared fail-closed classification of firewall changes affecting management traffic.

use kcc_catalog::Risk;
use kcc_rci::ObjectName;

use crate::{RouterCtx, interfaces, interfaces::membership};

/// Classifies the interfaces whose traffic a firewall change affects.
///
/// Failed detection is management risk, and so is a verdict that cannot tell which
/// interface carries kcc's connection.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, topology reads do not change router state.
#[inline]
pub async fn interfaces_risk(router: &RouterCtx, names: &[String]) -> Risk {
    if names.is_empty() {
        return Risk::Write;
    }
    classify(router, names).await
}

/// Delegates parent-bridge membership to the shared interface classifier.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, topology reads do not change router state.
async fn classify(router: &RouterCtx, names: &[String]) -> Risk {
    let mut highest = Risk::Write;
    for name in names {
        let found = match ObjectName::try_from(name.clone()) {
            Ok(object) => interfaces::detect_management(router, &object)
                .await
                .map_or(Risk::Management, interfaces::ManagementVerdict::risk),
            Err(_error) => Risk::Management,
        };
        highest = highest.max(found);
    }
    highest
}

/// Classifies every interface currently carrying a list, failing closed on unreadable bindings.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, configuration and topology reads do not change router state.
pub(super) async fn list_risk(router: &RouterCtx, list: &str) -> Risk {
    let lines = match membership::configuration_lines(router).await {
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
    classify(router, &names).await
}
