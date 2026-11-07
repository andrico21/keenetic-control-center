//! Unit tests of the active connection rows: endpoints sort by address, then port.
#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]

use super::endpoint_key;
use crate::table::rows::SortKey;

#[test]
fn ipv4_endpoints_sort_by_address_then_port_and_other_forms_as_text() {
    let low = endpoint_key(Some("192.0.2.20:10000"));
    let high = endpoint_key(Some("192.0.2.100:80"));
    assert!(low < high, "192.0.2.20 sorts before 192.0.2.100");
    let http = endpoint_key(Some("192.0.2.20:80"));
    let https = endpoint_key(Some("192.0.2.20:443"));
    assert!(http < https, "the same address sorts by port");
    assert_eq!(
        endpoint_key(Some("2001:db8::1")),
        SortKey::text("2001:db8::1"),
        "another form sorts as text"
    );
    assert_eq!(
        endpoint_key(None),
        SortKey::Missing,
        "a missing endpoint sorts last"
    );
}
