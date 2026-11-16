//! Static routes: IPv4 and IPv6 routes added and removed through the pages with read-back,
//! a value refused before anything is sent, and the routing table.

use axum::http::StatusCode;
use kcc_i18n::keys;
use url::form_urlencoded::byte_serialize;

use crate::{
    get, post,
    support::{
        outcome::TestResult,
        page::en,
        web::{Fixture, ROUTER},
    },
};

/// `value` encoded for a query string.
fn encoded(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

#[tokio::test]
async fn ipv4_route_is_added_and_removed_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let page = get(&fixture, &admin, "/ui/r/home/routing", StatusCode::OK).await?;
    assert!(
        page.contains(&en(keys::WEB_ROUTING_STATIC_EMPTY)),
        "no static route yet"
    );
    assert!(
        page.contains("hx-get=\"/ui/r/home/routing/route/new?family=ipv4\""),
        "Add route"
    );
    let fields = [
        ("network", "198.51.100.0"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
        ("interface", "ISP"),
        ("metric", "7"),
    ];
    let added = post(
        &fixture,
        &admin,
        ("/ui/r/home/routing/route/new?family=ipv4", &fields),
        StatusCode::OK,
    )
    .await?;
    assert!(
        added.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "toast: {added}"
    );
    assert!(added.contains("id=\"unsaved-badge\""), "the unsaved badge");
    assert!(
        added.contains("198.51.100.0/24"),
        "the routes read back: {added}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip route 198.51.100.0 255.255.255.0 192.0.2.254 ISP 7"),
        "the router has it"
    );
    assert_eq!(fixture.backups()?, 1, "backed up before the change");
    let remove = "/ui/r/home/routing/route/remove?family=ipv4&destination=198.51.100.0&mask=255.255.255.0&gateway=192.0.2.254&interface=ISP&metric=7";
    assert!(
        added.contains(&remove.replace('&', "&#38;")),
        "the region links the removal: {added}"
    );
    let dialog = get(&fixture, &admin, remove, StatusCode::OK).await?;
    assert!(
        dialog.contains(&en(keys::WEB_ROUTING_REMOVE_TEXT)),
        "asks first"
    );
    let removed = post(&fixture, &admin, (remove, &[]), StatusCode::OK).await?;
    assert!(
        removed.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "{removed}"
    );
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("ip route 198.51.100.0"),
        "gone from the router"
    );
    assert!(
        removed.contains(&en(keys::WEB_ROUTING_STATIC_EMPTY)),
        "read back"
    );
    let again = post(&fixture, &admin, (remove, &[]), StatusCode::OK).await?;
    assert!(
        again.contains(&en(keys::WEB_ROUTING_GONE)),
        "a stale removal: {again}"
    );
    assert!(
        fixture.audited("web.routing_route_remove", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn ipv6_route_is_added_and_removed_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let fields = [
        ("prefix", "2001:db8:7::/64"),
        ("gateway", "2001:db8::1"),
        ("interface", "ISP"),
    ];
    let added = post(
        &fixture,
        &admin,
        ("/ui/r/home/routing/route/new?family=ipv6", &fields),
        StatusCode::OK,
    )
    .await?;
    assert!(added.contains("2001:db8:7::/64"), "read back: {added}");
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ipv6 route 2001:db8:7::/64 ISP 2001:db8::1"),
        "the router has it"
    );
    let page = get(&fixture, &admin, "/ui/r/home/routing/ipv6", StatusCode::OK).await?;
    assert!(page.contains("2001:db8:7::/64"), "listed: {page}");
    let remove = format!(
        "/ui/r/home/routing/route/remove?family=ipv6&destination={}&gateway={}&interface=ISP",
        encoded("2001:db8:7::/64"),
        encoded("2001:db8::1")
    );
    let removed = post(&fixture, &admin, (&remove, &[]), StatusCode::OK).await?;
    assert!(
        removed.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "{removed}"
    );
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("ipv6 route 2001:db8:7::/64"),
        "gone"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_route_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let fields = [
        ("network", "198.51.100.300"),
        ("mask", "255.255.255.0"),
        ("gateway", "192.0.2.254"),
    ];
    let refused = post(
        &fixture,
        &admin,
        ("/ui/r/home/routing/route/new?family=ipv4", &fields),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_ROUTING_ERROR_IPV4)),
        "field error"
    );
    assert!(
        refused.contains("value=\"198.51.100.300\""),
        "the value as typed"
    );
    let missing_via = [("network", "198.51.100.0"), ("mask", "255.255.255.0")];
    let no_via = post(
        &fixture,
        &admin,
        ("/ui/r/home/routing/route/new?family=ipv4", &missing_via),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(
        no_via.contains(&en(keys::WEB_ROUTING_ERROR_VIA)),
        "a gateway or interface"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    assert!(
        fixture.audited("web.routing_route_add", "validation_failed")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn the_routing_table_lists_learned_and_static_routes() -> TestResult {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    drop(
        client
            .parse("ip route 203.0.113.0 255.255.255.0 192.0.2.253")
            .await?,
    );
    let viewer = fixture.login("viewer").await?;
    let table = get(
        &fixture,
        &viewer,
        "/ui/r/home/routing/table",
        StatusCode::OK,
    )
    .await?;
    assert!(
        table.contains("0.0.0.0/0"),
        "the learned default route: {table}"
    );
    assert!(table.contains("boot"), "where the router got it");
    assert!(table.contains("203.0.113.0/24"), "the static route");
    assert!(
        table.contains(&en(keys::WEB_ROUTING_SOURCE_STATIC)),
        "marked static"
    );
    let ipv6 = get(
        &fixture,
        &viewer,
        "/ui/r/home/routing/table/ipv6",
        StatusCode::OK,
    )
    .await?;
    assert!(ipv6.contains("2001:db8:1::/48"), "the IPv6 table: {ipv6}");
    let sorted = get(
        &fixture,
        &viewer,
        "/ui/r/home/routing/table?sort=destination&dir=desc",
        StatusCode::OK,
    )
    .await?;
    let static_at = sorted.find("203.0.113.0/24").ok_or("static row")?;
    let default_at = sorted.find("0.0.0.0/0").ok_or("default row")?;
    assert!(static_at < default_at, "sorted by destination, descending");
    Ok(())
}
