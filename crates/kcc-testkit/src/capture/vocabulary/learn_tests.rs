//! Which words of one capture run are the firmware's.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::learn;
use crate::capture::{Captured, Item, Raw, RawBody, Request};

/// A captured JSON answer.
fn answer(name: &str, request: Request, value: Value) -> Captured {
    (Item::new(name, request), Ok(RawBody(Raw::Json(value))))
}

/// Field keys at three places, configuration keywords and request words are the firmware's
/// (todo 12).
///
/// A row field at three places, a configuration keyword and a word of the capture's own
/// requests are; a rarer key, a key repeated at one place of `rci-root` and its `show rc`
/// answers, a key of a name-keyed map, a name repeated as a scalar key and a key shaped like
/// a MAC are not.
///
/// # Panics
///
/// Panics when a word is classified wrongly.
#[test]
fn schema_keys_occur_in_three_objects_and_config_keywords_count() {
    let mac = format!("a4b1c2{}", "d3e4f5");
    let row = |extra: Value| {
        let mut row = json!({"name": "a", "hostname": "b", mac.clone(): 1_u8});
        if let (Some(target), Value::Object(more)) = (row.as_object_mut(), extra) {
            target.extend(more);
        }
        json!([row])
    };
    let users = json!({"user": {"Owner-Name": {"tag": ["cli"]}}});
    let repeated = json!({"system": {"twice-seen": 1_u8}, "user": {"Owner-Name": {}}});
    let named = |index: u8| json!({"Plantedfield": index, "host": [{"name": "Plantedfield"}]});
    let captured = vec![
        answer(
            "show-ip-hotspot",
            Request::Show("show/ip/hotspot"),
            row(json!({"rare": 1_u8})),
        ),
        answer("show-ip-arp", Request::Show("show/ip/arp"), row(json!({}))),
        answer(
            "show-ip-dhcp-bindings",
            Request::Show("show/ip/dhcp/bindings"),
            row(json!({})),
        ),
        answer("rci-root", Request::Root, repeated.clone()),
        answer(
            "show-rc-system",
            Request::ShowRc(&["system"]),
            repeated.clone(),
        ),
        answer("show-rc-user", Request::ShowRc(&["user"]), repeated),
        answer("show-rc-users", Request::ShowRc(&["user"]), users.clone()),
        answer("whoami", Request::Get("whoami"), users),
        answer("show-version", Request::Show("show/version"), named(1)),
        answer("show-system", Request::Show("show/system"), named(2)),
        answer("show-ndns", Request::Show("show/ndns"), named(3)),
        (
            Item::new("running-config", Request::RunningConfig),
            Ok(RawBody(Raw::Config(Zeroizing::new(
                "rename Wireguard0\nip route 192.0.2.0 255.255.255.0 Bridge0\n".to_owned(),
            )))),
        ),
    ];
    let vocabulary = learn(&captured);
    for word in [
        "name",
        "hostname",
        "rename",
        "ip",
        "name-server",
        "hotspot",
        "user",
    ] {
        assert!(vocabulary.is_key(word), "{word} is a firmware word");
    }
    assert!(vocabulary.holds("HostName"), "a case variant is held");
    for word in [
        "rare",
        "twice-seen",
        "Plantedfield",
        mac.as_str(),
        "Owner-Name",
        "Bridge0",
    ] {
        assert!(
            !vocabulary.is_key(word),
            "word {} is not a firmware word",
            word.len()
        );
    }
}
