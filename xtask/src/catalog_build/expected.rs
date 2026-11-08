//! Structural catalog facts shared by the hermetic and the cache-backed catalog tests.
//!
//! Every fact is a command path, argument name, type tag or keyword literal taken from
//! the generated catalog; no manual prose is stored here.

use alloc::collections::BTreeSet;

use serde_json::Value;

/// Documented value-column keyword literals (space-separated) each argument must retain.
pub(super) const KEYWORD_LITERALS: [(&str, &str, &str); 11] = [
    (
        "user tag",
        "tag",
        "afp cifs cli ftp http http-proxy manager printers readonly vpn-dlna",
    ),
    (
        "crypto ike proposal integrity",
        "integrity",
        "md5 sha1 sha256 sha384 sha512",
    ),
    (
        "crypto ipsec transform-set hmac",
        "hmac",
        "esp-md5-hmac esp-null-hmac esp-sha1-hmac esp-sha256-hmac esp-sha512-hmac",
    ),
    (
        "ip ssh cipher",
        "cipher",
        "aes128-ctr aes256-ctr chacha20-poly1305@openssh.com",
    ),
    ("interface channel", "channel", "auto number"),
    (
        "ip ftp client-charset",
        "charset",
        "cp-037 cp-1026 cp-1250 cp-1251 cp-1252 cp-1253 cp-1254 cp-1255 cp-1256 cp-1257 \
         cp-1258 cp-424 cp-437 cp-500 cp-737 cp-775 cp-850 cp-852 cp-855 cp-856 cp-857 \
         cp-860 cp-861 cp-862 cp-863 cp-864 cp-865 cp-866 cp-869 cp-874 iso-8859-1 \
         iso-8859-10 iso-8859-11 iso-8859-12 iso-8859-13 iso-8859-14 iso-8859-15 \
         iso-8859-16 iso-8859-2 iso-8859-3 iso-8859-4 iso-8859-5 iso-8859-6 iso-8859-7 \
         iso-8859-8 iso-8859-9 koi8-r koi8-u kz-1048 mac-celtic mac-centeuro mac-croatian \
         mac-cyrillic mac-gaelic mac-greek mac-icelandic mac-inuit mac-roman mac-romanian \
         mac-turkish mac-ukrainian nextstep utf-16 utf-16be utf-16le utf-32 utf-32be \
         utf-32le utf-8",
    ),
    ("show ip route", "direction", "ascending descending"),
    (
        "system button",
        "handler",
        "FactoryReset Reboot WifiGuestApToggle WifiToggle WpsStartAllMainAp WpsStartMainAp \
         WpsStartMainAp5",
    ),
    ("nvox sip dtmf-mode", "mode", "inband rfc2833 sip-info"),
    (
        "dns-proxy filter engine",
        "engine",
        "interceptor nextdns opkg public skydns",
    ),
    ("torrent io-priority", "io-priority", "low normal"),
];

/// Arguments whose generated type tag is fixed, including the ambiguous `Prefix`,
/// `Policy`/`Schedule` and `password` table rows.
pub(super) const TYPED_ARGUMENTS: [(&str, &str, &str); 14] = [
    ("ip route", "gateway", "IpAddress"),
    ("ip route", "host", "IpAddress"),
    ("ip route", "network", "IpAddress"),
    ("ip route", "mask", "IpMask"),
    ("ip route", "interface", "Interface"),
    ("ipv6 route", "prefix", "IpAddressMask"),
    ("dyndns profile password", "password", "Password"),
    ("interface web-api password", "password", "Password"),
    ("ip policy", "name", "ObjectName"),
    ("ip hotspot host", "policy", "ObjectName"),
    ("ip hotspot host", "schedule", "ObjectName"),
    ("interface schedule", "schedule", "ObjectName"),
    (
        "system configuration fail-safe timer",
        "interval",
        "Integer",
    ),
    ("ip static", "to-host", "MacAddress"),
];

/// Keyword arguments whose literal set is exact.
pub(super) const EXACT_KEYWORDS: [(&str, &str, &[&str]); 2] = [
    (
        "interface security-level",
        "level",
        &["private", "protected", "public"],
    ),
    (
        "system configuration fail-safe timer",
        "action",
        &["reboot"],
    ),
];

/// The complete argument set of `ip static`.
const IP_STATIC_ARGUMENTS: [&str; 10] = [
    "address",
    "end-port",
    "interface",
    "mask",
    "port",
    "protocol",
    "to-address",
    "to-host",
    "to-interface",
    "to-port",
];

/// Finds a serialized command by its full path.
fn command<'commands>(commands: &'commands [Value], path: &str) -> Option<&'commands Value> {
    commands
        .iter()
        .find(|command| command.get("path").and_then(Value::as_str) == Some(path))
}

/// Returns the keyword literal set of `argument`.
///
/// # Errors
///
/// Returns a problem description when the argument is missing or not a keyword.
fn keyword_values(
    commands: &[Value],
    path: &str,
    argument: &str,
) -> Result<BTreeSet<String>, String> {
    let value = command(commands, path)
        .and_then(|command| command.get("arguments")?.get(argument))
        .ok_or_else(|| format!("{path} {argument}: missing"))?;
    if value.get("type").and_then(Value::as_str) != Some("Keyword") {
        return Err(format!("{path} {argument}: not a keyword: {value}"));
    }
    Ok(value
        .get("values")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

/// Lists keyword arguments that lost a documented literal.
pub(super) fn keyword_problems(commands: &[Value]) -> Vec<String> {
    KEYWORD_LITERALS
        .iter()
        .filter_map(
            |(path, argument, expected)| match keyword_values(commands, path, argument) {
                Ok(actual) => {
                    let missing: Vec<&str> = expected
                        .split_whitespace()
                        .filter(|literal| !actual.contains(*literal))
                        .collect();
                    (!missing.is_empty())
                        .then(|| format!("{path} {argument}: lost literals {missing:?}"))
                }
                Err(problem) => Some(problem),
            },
        )
        .collect()
}

/// Lists arguments whose type tag or exact keyword set differs from the facts.
pub(super) fn typing_problems(commands: &[Value]) -> Vec<String> {
    let typed = TYPED_ARGUMENTS.iter().filter_map(|(path, argument, tag)| {
        let actual = command(commands, path)
            .and_then(|command| command.get("arguments")?.get(*argument)?.get("type"))
            .and_then(Value::as_str);
        (actual != Some(*tag)).then(|| format!("{path} {argument}: {actual:?}, expected {tag}"))
    });
    let exact = EXACT_KEYWORDS
        .iter()
        .filter_map(|(path, argument, expected)| {
            let wanted: BTreeSet<String> = expected.iter().copied().map(str::to_owned).collect();
            match keyword_values(commands, path, argument) {
                Ok(actual) if actual == wanted => None,
                Ok(actual) => Some(format!(
                    "{path} {argument}: {actual:?}, expected {wanted:?}"
                )),
                Err(problem) => Some(problem),
            }
        });
    typed.chain(exact).collect()
}

/// Lists structural spot facts (argument sets, flags, kinds) that no longer hold.
pub(super) fn spot_problems(commands: &[Value]) -> Vec<String> {
    let field = |path: &str, name: &str| {
        command(commands, path)
            .and_then(|found| found.get(name))
            .cloned()
    };
    let ip_static: Option<BTreeSet<String>> = command(commands, "ip static")
        .and_then(|command| command.get("arguments")?.as_object())
        .map(|arguments| arguments.keys().cloned().collect());
    let wanted: BTreeSet<String> = IP_STATIC_ARGUMENTS
        .iter()
        .copied()
        .map(str::to_owned)
        .collect();
    let checks = [
        (
            "ip static argument set",
            ip_static.as_ref() == Some(&wanted),
        ),
        (
            "ip static prefix_no",
            field("ip static", "prefix_no") == Some(Value::Bool(true)),
        ),
        (
            "ip static multiple_input",
            field("ip static", "multiple_input") == Some(Value::Bool(true)),
        ),
        (
            "fail-safe timer prefix_no",
            field("system configuration fail-safe timer", "prefix_no") == Some(Value::Bool(true)),
        ),
        (
            "show running-config kind",
            field("show running-config", "kind") == Some(Value::from("Show")),
        ),
        (
            "wireguard private-key interface_type",
            field("interface wireguard private-key", "interface_type")
                == Some(Value::from("Wireguard")),
        ),
    ];
    checks
        .into_iter()
        .filter(|(_, holds)| !holds)
        .map(|(name, _)| name.to_owned())
        .collect()
}
