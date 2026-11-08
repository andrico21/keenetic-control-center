//! Assumed VPN server running-configuration projections.

use serde_json::{Map, Value, json};

use super::{insert_path, matching};

/// Projects the supported non-secret server fields from mutable commands.
pub(super) fn extend(root: &mut Map<String, Value>, lines: &[Vec<String>]) {
    crypto_maps(root, lines);
    for server in ["vpn-server", "sstp-server", "oc-server"] {
        let mut routes = Vec::new();
        for words in matching(lines, &[server]) {
            match words {
                [field, interface] if field == "interface" => {
                    insert_path(root, &[server, field], json!({"interface":interface}));
                }
                [field, begin] if field == "pool-range" => {
                    insert_path(root, &[server, field], json!({"begin":begin}));
                }
                [field, begin, size] if field == "pool-range" => {
                    if let Ok(number) = size.parse::<u16>() {
                        insert_path(root, &[server, field], json!({"begin":begin,"size":number}));
                    }
                }
                [field, primary] if field == "dns-servers" => {
                    insert_path(root, &[server, field], json!({"dns1":primary}));
                }
                [field, primary, secondary] if field == "dns-servers" => insert_path(
                    root,
                    &[server, field],
                    json!({"dns1":primary,"dns2":secondary}),
                ),
                [field, address, mask] if field == "route" => {
                    routes.push(json!({"address":address,"mask":mask}));
                }
                _ => {}
            }
        }
        insert_path(root, &[server, "route"], Value::Array(routes));
    }
    let interfaces = matching(lines, &["wireguard-server", "interface"])
        .filter_map(|words| words.first())
        .map(|interface| json!({"interface":interface}))
        .collect();
    insert_path(
        root,
        &["wireguard-server", "interface"],
        Value::Array(interfaces),
    );
}

/// Projects the exact named virtual-IP map rather than a global server singleton.
fn crypto_maps(root: &mut Map<String, Value>, lines: &[Vec<String>]) {
    for words in matching(lines, &["crypto", "map"]) {
        let Some((name, tail)) = words.split_first() else {
            continue;
        };
        match tail {
            [] => insert_path(
                root,
                &["crypto", "map", name, "virtual-ip", "enable"],
                json!(false),
            ),
            [virtual_ip, enable] if virtual_ip == "virtual-ip" && enable == "enable" => {
                insert_path(
                    root,
                    &["crypto", "map", name, "virtual-ip", "enable"],
                    json!(true),
                );
            }
            [virtual_ip, range, begin] if virtual_ip == "virtual-ip" && range == "range" => {
                insert_path(
                    root,
                    &["crypto", "map", name, "virtual-ip", "range"],
                    json!({"begin":begin}),
                );
            }
            [virtual_ip, range, begin, end] if virtual_ip == "virtual-ip" && range == "range" => {
                let value = match end.parse::<u16>() {
                    Ok(size) => json!({"begin":begin,"size":size}),
                    Err(_error) => json!({"begin":begin,"end":end}),
                };
                insert_path(root, &["crypto", "map", name, "virtual-ip", "range"], value);
            }
            [virtual_ip, dns, primary] if virtual_ip == "virtual-ip" && dns == "dns-servers" => {
                insert_path(
                    root,
                    &["crypto", "map", name, "virtual-ip", "dns-servers"],
                    json!({"dns1":primary}),
                );
            }
            [virtual_ip, dns, primary, secondary]
                if virtual_ip == "virtual-ip" && dns == "dns-servers" =>
            {
                insert_path(
                    root,
                    &["crypto", "map", name, "virtual-ip", "dns-servers"],
                    json!({"dns1":primary,"dns2":secondary}),
                );
            }
            _ => {}
        }
    }
}
