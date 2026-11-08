//! Accepted simulator CLI grammar and replacement identities.

use super::{engine::Shape, tokens::starts_with};

/// Accepted leaf grammar beneath a context.
#[derive(Clone, Copy)]
struct LeafRule {
    /// Literal leaf prefix.
    prefix: &'static [&'static str],
    /// Minimum leaf length.
    minimum: usize,
    /// Optional maximum leaf length.
    maximum: Option<usize>,
    /// Words forming the replacement identity.
    identity_words: usize,
}

/// Interface context shapes.
const INTERFACE_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["ip", "address"], 3, Some(4), 2),
    leaf(&["ip", "global"], 2, Some(3), 2),
    leaf(&["ip", "mtu"], 3, Some(3), 2),
    leaf(&["ipcp", "default-route"], 2, Some(2), 2),
    leaf(&["authentication", "identity"], 3, Some(3), 2),
    leaf(&["connect", "via"], 3, Some(3), 2),
    leaf(&["ip", "access-group"], 4, Some(4), 4),
    leaf(&["security-level"], 2, Some(2), 1),
    leaf(&["up"], 1, Some(1), 1),
    leaf(&["down"], 1, Some(1), 1),
    leaf(&["ssid"], 2, Some(2), 1),
    leaf(&["authentication", "password"], 3, Some(4), 2),
    leaf(&["authentication", "wpa-psk"], 3, Some(4), 2),
    leaf(&["ipsec", "preshared-key"], 3, Some(4), 2),
    leaf(&["encryption"], 2, Some(3), 1),
    leaf(&["hide-ssid"], 1, Some(2), 1),
    leaf(&["channel"], 2, None, 1),
    leaf(&["schedule"], 2, Some(2), 1),
    leaf(&["vlan-id"], 2, Some(2), 1),
    leaf(&["include"], 2, None, 2),
    leaf(&["inherit"], 2, None, 2),
    leaf(&["switchport"], 2, None, 2),
    leaf(&["wireguard", "private-key"], 2, Some(3), 2),
    leaf(&["wireguard", "private-key", "ns3"], 4, Some(4), 2),
    leaf(&["wireguard", "obfs-key"], 3, Some(4), 2),
    leaf(&["wireguard", "listen-port"], 3, Some(3), 2),
    leaf(&["wireguard", "peer"], 3, Some(3), 3),
    leaf(&["wireguard", "peer"], 4, None, 4),
];

/// DHCP pool context shapes.
const DHCP_POOL_RULES: &[LeafRule] = &[
    leaf(&["range"], 3, Some(3), 1),
    leaf(&["default-router"], 2, Some(2), 1),
    leaf(&["dns-server"], 2, Some(3), 2),
    leaf(&["lease"], 2, Some(2), 1),
    leaf(&["bind"], 2, Some(2), 1),
    leaf(&["enable"], 1, Some(1), 1),
];

/// User context shapes.
const USER_RULES: &[LeafRule] = &[
    leaf(&["password", "plain"], 3, Some(3), 1),
    leaf(&["password", "md5"], 3, Some(3), 1),
    leaf(&["password", "nt"], 3, Some(3), 1),
    leaf(&["tag"], 2, Some(2), 2),
];

/// Secret-bearing IPsec profile leaves supported by the simulator.
const IPSEC_PROFILE_RULES: &[LeafRule] = &[
    leaf(&["preshared-key"], 2, Some(3), 1),
    leaf(&["xauth-password"], 2, Some(3), 1),
];

/// Mutable virtual-IP server leaves beneath a named crypto map.
const CRYPTO_MAP_RULES: &[LeafRule] = &[
    leaf(&["virtual-ip", "enable"], 2, Some(2), 2),
    leaf(&["virtual-ip", "range"], 3, Some(4), 2),
    leaf(&["virtual-ip", "dns-servers"], 3, Some(4), 2),
];

/// Connection-policy context shapes.
const POLICY_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["permit"], 2, None, 2),
    leaf(&["multipath"], 1, None, 1),
    leaf(&["route"], 2, None, 2),
    leaf(&["rate-limit"], 3, None, 3),
    leaf(&["standalone"], 1, Some(1), 1),
];

/// Access-list context shapes.
const ACCESS_LIST_RULES: &[LeafRule] = &[
    exact(&["permit"], 2),
    exact(&["deny"], 2),
    leaf(&["rule"], 2, None, 2),
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["disable"], 1, Some(2), 1),
    leaf(&["schedule"], 2, Some(2), 1),
];

/// Builds one exact-removal leaf rule.
const fn exact(prefix: &'static [&'static str], minimum: usize) -> LeafRule {
    LeafRule {
        prefix,
        minimum,
        maximum: None,
        identity_words: usize::MAX,
    }
}

/// Schedule context shapes.
const SCHEDULE_RULES: &[LeafRule] = &[
    leaf(&["description"], 2, Some(2), 1),
    leaf(&["action"], 2, None, 2),
    leaf(&["weekly"], 2, None, 2),
];

/// Builds one constant leaf rule.
const fn leaf(
    prefix: &'static [&'static str],
    minimum: usize,
    maximum: Option<usize>,
    identity_words: usize,
) -> LeafRule {
    LeafRule {
        prefix,
        minimum,
        maximum,
        identity_words,
    }
}

/// Classifies context commands through the local shape table.
pub(super) fn classify(command: &[String]) -> Option<Shape> {
    let context = [
        (&["interface"][..], 2_usize, INTERFACE_RULES),
        (&["ip", "dhcp", "pool"][..], 4_usize, DHCP_POOL_RULES),
        (&["ip", "policy"][..], 3_usize, POLICY_RULES),
        (&["access-list"][..], 2_usize, ACCESS_LIST_RULES),
        (&["user"][..], 2_usize, USER_RULES),
        (&["schedule"][..], 2_usize, SCHEDULE_RULES),
        (&["crypto", "map"][..], 3_usize, CRYPTO_MAP_RULES),
        (
            &["crypto", "ipsec", "profile"][..],
            4_usize,
            IPSEC_PROFILE_RULES,
        ),
    ];
    for (prefix, context_words, rules) in context {
        if starts_with(command, prefix) && command.len() >= context_words {
            if command.len() == context_words {
                return Some(Shape {
                    context_words,
                    identity_words: 0,
                    exact_removal: false,
                });
            }
            let leaf_words = command.get(context_words..)?;
            let rule = rules.iter().find(|rule| matches_rule(leaf_words, rule))?;
            return Some(Shape {
                context_words,
                identity_words: rule.identity_words,
                exact_removal: rule.identity_words == usize::MAX,
            });
        }
    }
    classify_top_level(command)
}

/// Classifies top-level command families.
fn classify_top_level(command: &[String]) -> Option<Shape> {
    additional_shape(command).or_else(|| ordinary_shape(command))
}

/// Classifies stateful maintenance and server commands.
fn additional_shape(command: &[String]) -> Option<Shape> {
    if starts_with(command, &["mws", "acquire"]) && command.len() == 3 {
        return Some(Shape {
            context_words: 0,
            identity_words: 3,
            exact_removal: true,
        });
    }
    if starts_with(command, &["ntp"]) && matches!(command.len(), 2 | 3) {
        return Some(Shape {
            context_words: 0,
            identity_words: 2,
            exact_removal: false,
        });
    }
    if command.first().is_some_and(|word| {
        matches!(
            word.as_str(),
            "vpn-server" | "sstp-server" | "oc-server" | "wireguard-server"
        )
    }) && command.len() >= 3
    {
        return Some(Shape {
            context_words: 0,
            identity_words: if starts_with(command, &["wireguard-server", "interface"])
                || starts_with(command, &["oc-server", "route"])
            {
                command.len()
            } else {
                2
            },
            exact_removal: false,
        });
    }
    if starts_with(command, &["crypto", "ike", "key"]) && matches!(command.len(), 6..=8) {
        return Some(Shape {
            context_words: 0,
            identity_words: 4,
            exact_removal: false,
        });
    }
    None
}

/// Classifies the ordinary top-level configuration command families.
fn ordinary_shape(command: &[String]) -> Option<Shape> {
    let identity_words = if starts_with(command, &["ip", "dhcp", "host"])
        && matches!(command.len(), 4 | 5)
    {
        4
    } else if starts_with(command, &["ip", "hotspot", "host"]) && command.len() >= 5 {
        command.len().min(6)
    } else if starts_with(command, &["ip", "hotspot", "policy"]) && command.len() == 5 {
        4
    } else if starts_with(command, &["ip", "hotspot", "default-policy"]) && command.len() == 4 {
        3
    } else if (starts_with(command, &["system", "hostname"])
        || starts_with(command, &["system", "description"])
        || starts_with(command, &["system", "clock", "timezone"]))
        && matches!(command.len(), 3 | 4)
    {
        command.len().saturating_sub(1)
    } else if starts_with(command, &["cloud", "control2", "security-level"]) && command.len() == 4 {
        3
    } else if starts_with(command, &["ip", "http", "proxy"]) && command.len() == 4 {
        4
    } else if starts_with(command, &["ip", "http", "proxy"]) && command.len() == 8 {
        5
    } else if starts_with(command, &["ip", "nat"]) && command.len() == 3 {
        3
    } else if starts_with(command, &["service"]) && command.len() == 2 {
        2
    } else if starts_with(command, &["ip", "http"])
        || starts_with(command, &["ip", "ssh"])
        || starts_with(command, &["ip", "telnet"])
    {
        command.len().saturating_sub(1)
    } else if starts_with(command, &["dns-proxy", "tls", "upstream"])
        || starts_with(command, &["dns-proxy", "https", "upstream"])
        || starts_with(command, &["ip", "host"])
        || starts_with(command, &["ip", "name-server"])
        || starts_with(command, &["object-group", "fqdn"])
        || starts_with(command, &["ndns"])
        || starts_with(command, &["system", "log"])
        || starts_with(command, &["components", "install"])
        || starts_with(command, &["components", "remove"])
        || starts_with(command, &["ipv6", "route"])
        || starts_with(command, &["ip", "static"])
        || starts_with(command, &["ip", "route"])
    {
        command.len()
    } else {
        return None;
    };
    Some(Shape {
        context_words: 0,
        identity_words,
        exact_removal: starts_with(command, &["ip", "route"])
            || starts_with(command, &["ipv6", "route"])
            || starts_with(command, &["ip", "static"]),
    })
}

/// Tests one leaf rule.
fn matches_rule(words: &[String], rule: &LeafRule) -> bool {
    starts_with(words, rule.prefix)
        && words.len() >= rule.minimum
        && rule.maximum.is_none_or(|maximum| words.len() <= maximum)
}
