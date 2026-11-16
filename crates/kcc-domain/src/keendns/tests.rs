//! Which KeenDNS name kcc reaches the router by.

use super::reached_by;

/// W4-11: releasing the name kcc reaches the router by is a management change; any
/// other name, an address or a name that only shares letters with it is not.
#[test]
fn the_name_kcc_reaches_the_router_by_is_management() {
    for (host, expected) in [
        (Some("home.example.net"), true),
        (Some("home.example.net."), true),
        (Some("admin.home.example.net"), true),
        (Some("myhome.example.net"), false),
        (Some("other.example.net"), false),
        (Some("203.0.113.7"), false),
        (None, false),
    ] {
        assert_eq!(reached_by(host, "home.example.net"), expected, "{host:?}");
    }
}
