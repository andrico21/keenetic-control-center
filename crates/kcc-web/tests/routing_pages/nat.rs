//! Port forwarding, address translation and the router's active connections.
//!
//! A port is forwarded and the rule removed with read-back, address translation is added to
//! and taken off an interface, and active connections come in pages of at most 200 rows,
//! sorted and filtered within the page.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    get, post,
    support::{outcome::TestResult, page::en, web::Fixture},
};

/// The data rows of the first table body in `page`.
fn rows(page: &str) -> usize {
    page.split_once("<tbody>")
        .and_then(|(_, body)| body.split_once("</tbody>"))
        .map_or(0, |(body, _)| body.matches("<tr>").count())
}

#[tokio::test]
async fn a_port_forward_is_added_and_removed_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let fields = [
        ("protocol", "tcp"),
        ("interface", "ISP"),
        ("port", "8443"),
        ("target", "192.0.2.44"),
        ("to_port", "443"),
    ];
    let added = post(
        &fixture,
        &admin,
        ("/ui/r/home/nat/forward/new", &fields),
        StatusCode::OK,
    )
    .await?;
    assert!(added.contains(&en(keys::WEB_KIT_DONE_UNSAVED)), "{added}");
    assert!(
        added.contains("192.0.2.44") && added.contains("8443"),
        "read back: {added}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip static tcp ISP 8443 192.0.2.44 443"),
        "the router has it"
    );
    let remove = "/ui/r/home/nat/forward/remove?interface=ISP&target=192.0.2.44&protocol=tcp&port=8443&to=443";
    assert!(
        added.contains(&remove.replace('&', "&#38;")),
        "Remove links it: {added}"
    );
    drop(post(&fixture, &admin, (remove, &[]), StatusCode::OK).await?);
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("ip static tcp ISP 8443"),
        "gone"
    );
    let ranged = [
        ("protocol", "udp"),
        ("interface", "ISP"),
        ("port", "5000"),
        ("end_port", "4000"),
        ("target", "192.0.2.45"),
    ];
    let refused = post(
        &fixture,
        &admin,
        ("/ui/r/home/nat/forward/new", &ranged),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_NAT_ERROR_RANGE)),
        "{refused}"
    );
    Ok(())
}

#[tokio::test]
async fn address_translation_is_added_and_taken_off_an_interface() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(
        get(
            &fixture,
            &admin,
            "/ui/r/home/nat/interfaces",
            StatusCode::OK,
        )
        .await?,
    );
    drop(
        post(
            &fixture,
            &admin,
            ("/ui/r/home/nat/interface/new", &[("interface", "ISP")]),
            StatusCode::OK,
        )
        .await?,
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip nat ISP"),
        "added"
    );
    drop(
        post(
            &fixture,
            &admin,
            ("/ui/r/home/nat/interface/remove?name=ISP", &[]),
            StatusCode::OK,
        )
        .await?,
    );
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("ip nat ISP"),
        "taken off"
    );
    Ok(())
}

#[tokio::test]
async fn active_connections_come_in_router_pages_of_at_most_two_hundred() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    let base = "/ui/r/home/nat/sessions";
    let first = get(&fixture, &viewer, base, StatusCode::OK).await?;
    assert_eq!(rows(&first), 200, "a full page");
    assert!(first.contains("Connections 1 to 200"), "where the page is");
    assert!(first.contains("page=2"), "a next page: {first}");
    assert!(
        !first.contains(&en(keys::WEB_ADMIN_PAGE_PREVIOUS)),
        "no previous page"
    );
    let second = get(&fixture, &viewer, &format!("{base}?page=2"), StatusCode::OK).await?;
    assert_eq!(rows(&second), 200, "the second page");
    assert!(second.contains(&en(keys::WEB_ADMIN_PAGE_PREVIOUS)), "back");
    assert!(second.contains(&en(keys::WEB_ADMIN_PAGE_NEXT)), "on");
    let third = get(&fixture, &viewer, &format!("{base}?page=3"), StatusCode::OK).await?;
    assert_eq!(rows(&third), 80, "the last 80 of 480");
    assert!(third.contains("Connections 401 to 480"), "{third}");
    assert!(
        !third.contains(&en(keys::WEB_ADMIN_PAGE_NEXT)),
        "nothing after"
    );
    let pages: Vec<String> = fixture
        .handle()
        .request_log()
        .iter()
        .filter(|request| request.path() == "/rci/show/ip/nat")
        .map(|request| format!("{:?}", request.query()))
        .collect();
    assert_eq!(pages.len(), 3, "one router request a page");
    assert!(
        pages
            .iter()
            .all(|query| query.contains("\"limit\", \"200\"")),
        "{pages:?}"
    );
    let filtered = get(
        &fixture,
        &viewer,
        &format!("{base}?q=udp&page=1"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(rows(&filtered), 100, "half of the page is UDP");
    for (direction, leading, trailing) in [("asc", "TCP", "UDP"), ("desc", "UDP", "TCP")] {
        let path = format!("{base}?sort=protocol&dir={direction}&page=1");
        let sorted = get(&fixture, &viewer, &path, StatusCode::OK).await?;
        let before = sorted
            .find(&format!("<td>{leading}</td>"))
            .ok_or("leading protocol")?;
        let after = sorted
            .find(&format!("<td>{trailing}</td>"))
            .ok_or("trailing protocol")?;
        assert!(before < after, "sorted {direction} within the page");
    }
    Ok(())
}
