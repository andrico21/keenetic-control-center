//! Add route sends the canonical route the router stores, whatever its spelling: the
//! duplicate check and the read-back compare that route.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    post,
    support::{outcome::TestResult, page::en, web::Fixture},
};

/// W3-13: a network typed with host bits is the network the router stores, so the route
/// it already has is refused as a duplicate instead of sent again.
#[tokio::test]
async fn a_network_with_host_bits_is_the_stored_network() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let path = "/ui/r/home/routing/route/new?family=ipv4";
    let stored = [
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ];
    let _added = post(&fixture, &admin, (path, &stored), StatusCode::OK).await?;
    let typed = [
        ("network", "198.51.100.7"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ];
    let refused = post(
        &fixture,
        &admin,
        (path, &typed),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_ROUTING_ERROR_DUPLICATE)),
        "{refused}"
    );
    Ok(())
}

/// W3-13: an IPv6 prefix and gateway are sent in the canonical form the router stores and
/// reads back, whatever their spelling.
#[tokio::test]
async fn an_ipv6_route_is_sent_in_canonical_form() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let fields = [
        ("prefix", "2001:DB8:7:0:0::1/64"),
        ("gateway", "2001:DB8:0::1"),
        ("interface", "ISP"),
    ];
    let _added = post(
        &fixture,
        &admin,
        ("/ui/r/home/routing/route/new?family=ipv6", &fields),
        StatusCode::OK,
    )
    .await?;
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ipv6 route 2001:db8:7::/64 ISP 2001:db8::1"),
        "{}",
        fixture.handle().running_config_text()
    );
    Ok(())
}
