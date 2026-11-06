//! The DNS read model over configured trees of odd shapes.
#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
use kcc_domain::dns::{DnsConfiguration, DnsProxyState};
use serde_json::json;

use super::{DnsState, Protocol};

#[test]
fn configured_trees_become_rows_and_odd_shapes_are_skipped() {
    let proxy: DnsProxyState = serde_json::from_value(json!({
        "tls": {"upstream": [["9.9.9.9", "853", "sni", "dns.quad9.net"]]},
        "https": {"upstream": [["https://dns.example/dns-query"]]}
    }))
    .unwrap_or_default();
    let config: DnsConfiguration = serde_json::from_value(json!({
        "dns-proxy": {"route": {"object-group": [{"group": "video", "interface": "Wireguard0"}]},
            "filter": {"engine": "public", "profile": [{"name": "kids"}],
                "assign": {"host": [{"host": "02:00:00:00:11:01", "profile": "kids"}]}}},
        "ip": {"name-server": [{"address": "192.0.2.53"}, true], "host": {"domain": "nas.home", "address": "192.0.2.10"}},
        "object-group": {"fqdn": [{"name": "video", "include": [{"address": "example.com"}], "exclude": "cdn.example.com"}, 7_i32]}
    }))
    .unwrap_or_default();
    let state = DnsState { proxy, config };
    let servers: Vec<(Protocol, String, Option<String>)> = state
        .servers()
        .into_iter()
        .map(|(protocol, entry)| {
            (
                protocol,
                entry.name().to_owned(),
                entry.value(0).map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(
        servers,
        [
            (
                Protocol::Tls,
                "9.9.9.9".to_owned(),
                Some("853 sni dns.quad9.net".to_owned())
            ),
            (
                Protocol::Https,
                "https://dns.example/dns-query".to_owned(),
                None
            ),
            (Protocol::Plain, "192.0.2.53".to_owned(), None)
        ],
        "every protocol, the boolean skipped"
    );
    let records = state.records();
    assert_eq!(
        records.first().map(|entry| (entry.name(), entry.value(0))),
        Some(("nas.home", Some("192.0.2.10"))),
        "one object is one record"
    );
    let lists = state.lists();
    assert_eq!(lists.len(), 1, "the number is skipped");
    assert_eq!(
        lists.first().map(|entry| (entry.list(0), entry.list(1))),
        Some((
            vec!["example.com".to_owned()],
            vec!["cdn.example.com".to_owned()]
        )),
        "included and excluded"
    );
    assert_eq!(
        state
            .routes()
            .first()
            .map(|entry| (entry.name(), entry.value(0))),
        Some(("video", Some("Wireguard0"))),
        "route"
    );
    assert_eq!(state.engine().as_deref(), Some("public"), "engine");
    assert_eq!(state.profiles().len(), 1, "profiles");
    assert_eq!(
        state
            .assignments()
            .first()
            .map(|(host, entry)| (*host, entry.value(0))),
        Some((true, Some("kids"))),
        "assignment"
    );
    assert_eq!(state.intercept(), None, "not reported");
}
