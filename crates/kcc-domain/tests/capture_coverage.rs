//! The capture tool reads everything kcc reads, so a capture can replay every read offline.

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use kcc_testkit::capture::{CALL_SITES, Request, items};
    use serde_json::Value;

    /// Items kcc reads outside the domain descriptors (poller, telemetry, detection, diagnostics).
    const FIXED_EXTRAS: &[&str] = &[
        "show-identification",
        "show-system-mode",
        "show-interface-bands",
        "show-ip-arp",
        "show-ip-nat",
        "show-upnp-redirect",
        "show-mws-associations",
        "show-components-status",
        "show-clock-date",
        "show-ntp-status",
        "show-last-change",
        "show-internet-status",
        "show-rc-user",
        "show-rc-service",
        "show-rc-opkg",
        "show-rc-ip-policy",
        "show-rc-ip-nat",
        "show-rc-interface",
        "show-rc-dns",
        "show-rc-vpn-server",
        "show-rc-sstp-server",
        "show-rc-oc-server",
        "show-rc-wireguard-server",
        "show-rc-crypto",
        "components-list",
        "components-preview",
        "tools-ping",
        "show-log-stream",
        "show-log",
    ];

    /// Whether the `show rc` request `tree` reads the whole subtree at `path`.
    fn tree_contains(tree: &Value, path: &str) -> bool {
        let mut node = tree;
        for word in path.split(' ') {
            match node.get(word) {
                Some(Value::Object(inner)) if inner.is_empty() => return true,
                Some(inner) => node = inner,
                None => return false,
            }
        }
        false
    }

    /// Whether some item reads the catalog path `path`.
    fn covered(path: &str, requests: &[Request]) -> bool {
        let words = path.replace(' ', "/");
        match path {
            // The capture reads `show interface stat` once per interface listed by `show interface`.
            "show interface stat" => return requests.contains(&Request::Show("show/interface")),
            // Segment verification reads `show rc` below `interface`.
            "show rc" => return covered("interface", requests),
            _ => {}
        }
        if path.starts_with("show ") {
            return requests.iter().any(|request| match request {
                Request::Show(show) | Request::Continued(show, _, _) => *show == words,
                Request::Get(_)
                | Request::Root
                | Request::RunningConfig
                | Request::ShowRc(_)
                | Request::ShowLog
                | Request::InterfaceStat(_)
                | _ => false,
            });
        }
        requests.iter().any(|request| match request {
            Request::Continued(continued, _, _) => *continued == words,
            Request::ShowRc(_) => request
                .rc_tree()
                .is_some_and(|tree| tree_contains(&tree, path)),
            Request::Show(_)
            | Request::Get(_)
            | Request::Root
            | Request::RunningConfig
            | Request::ShowLog
            | Request::InterfaceStat(_)
            | _ => false,
        })
    }

    /// Every descriptor read (diagnostic tools aside) has a capture item: a `show` path a Show
    /// item with the same words, any other path a `show rc` tree or a continued exchange
    /// (todo 4).
    ///
    /// # Panics
    ///
    /// Panics naming the uncovered paths.
    #[test]
    fn every_descriptor_read_has_a_capture_item() {
        let requests: Vec<Request> = items().into_iter().map(|item| item.request).collect();
        let missing: BTreeSet<&str> = kcc_domain::registry()
            .iter()
            .flat_map(|domain| domain.read_ops)
            .map(|operation| operation.catalog_path)
            .filter(|path| !path.starts_with("tools "))
            .filter(|path| !covered(path, &requests))
            .collect();
        assert!(
            missing.is_empty(),
            "reads without a capture item: {missing:?}"
        );
    }

    /// Every call-site entry names an item, every item has one, and the reads kcc performs
    /// outside the descriptors are captured (todo 4).
    ///
    /// # Panics
    ///
    /// Panics naming the missing or unknown items.
    #[test]
    fn call_sites_and_fixed_extras_match_the_items() {
        let names: BTreeSet<String> = items().into_iter().map(|item| item.name).collect();
        let mapped: BTreeSet<String> = CALL_SITES
            .iter()
            .map(|(item, _)| (*item).to_owned())
            .collect();
        let unknown: Vec<&String> = mapped.difference(&names).collect();
        let unmapped: Vec<&String> = names.difference(&mapped).collect();
        let extras: Vec<&&str> = FIXED_EXTRAS
            .iter()
            .filter(|extra| !names.contains(**extra))
            .collect();
        assert!(
            unknown.is_empty(),
            "call sites name unknown items: {unknown:?}"
        );
        assert!(
            unmapped.is_empty(),
            "items without call sites: {unmapped:?}"
        );
        assert!(extras.is_empty(), "missing fixed items: {extras:?}");
        assert!(
            CALL_SITES.iter().all(|(_, sites)| !sites.is_empty()),
            "every item names at least one call site"
        );
    }
}
