//! The route-wipe guard: a router that answers one route's removal by clearing every static
//! route gets each of them back, and the page says so prominently.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    audited, get, html, post, said,
    support::{Fixture, ROUTER, TestResult},
};

#[tokio::test]
async fn a_router_wide_clear_shows_the_guard_banner_and_keeps_every_route() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().route_wipe_on_remove(true)).await?;
    let client = fixture.registry().client(ROUTER).await?;
    for line in [
        "ip route 198.51.100.0 255.255.255.0 192.0.2.254",
        "ip route 203.0.113.0 255.255.255.0 192.0.2.253 ISP",
    ] {
        drop(client.parse(line).await?);
    }
    let before = fixture.handle().running_config_text();
    let admin = fixture.login("admin").await?;
    let remove = "/ui/r/home/routing/route/remove?family=ipv4&destination=198.51.100.0&mask=255.255.255.0&gateway=192.0.2.254";
    let answer = post(&fixture, &admin, (remove, &[]), StatusCode::OK).await?;
    assert!(
        answer.contains("class=\"routing-guard\""),
        "the banner: {answer}"
    );
    assert!(answer.contains("role=\"alert\""), "announced at once");
    assert!(
        answer.contains(&said(keys::WEB_ROUTING_GUARD_TITLE)),
        "its title"
    );
    let mut args = FluentArgs::new();
    args.set("count", 2_u32);
    let text = html(&tr(Locale::En, keys::WEB_ROUTING_GUARD_TEXT, Some(&args)));
    assert!(
        answer.contains(&text),
        "nothing was lost, two routes back: {answer}"
    );
    assert!(
        answer.contains(&said(keys::WEB_ROUTING_GUARD_KEPT)),
        "the route stays"
    );
    for restored in [
        "ip route 198.51.100.0 255.255.255.0 192.0.2.254",
        "ip route 203.0.113.0 255.255.255.0 192.0.2.253 ISP",
    ] {
        assert!(answer.contains(restored), "named in the banner: {restored}");
        assert!(
            fixture.handle().running_config_text().contains(restored),
            "still on the router: {restored}"
        );
    }
    assert!(
        !answer.contains(&said(keys::WEB_KIT_DONE_UNSAVED)),
        "no success toast"
    );
    let after = fixture.handle().running_config_text();
    for line in before.lines().filter(|line| line.starts_with("ip route")) {
        assert!(after.contains(line), "every pre-change route: {line}");
    }
    assert!(
        audited(&fixture, "web.routing_route_wipe", "restored")?,
        "audited"
    );
    let page = get(&fixture, &admin, "/ui/r/home/routing", StatusCode::OK).await?;
    assert!(
        page.contains("198.51.100.0/24") && page.contains("203.0.113.0/24"),
        "listed"
    );
    Ok(())
}
