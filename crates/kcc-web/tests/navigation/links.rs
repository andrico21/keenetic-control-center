//! The section links of a router page, of a page without a router, and of a role that may
//! read one router only, each opened.

use crate::{
    ROUTER_PAGES, add_lab_routers, every_link_lands, nav_links, open_ok,
    support::{outcome::TestResult, page::text, web::Fixture},
};

/// On a router's page every section link opens that router's page of the section.
#[tokio::test]
async fn a_router_pages_links_open_that_routers_sections() -> TestResult {
    let fixture = Fixture::new().await?;
    let (lab_router, _lab_dir) = add_lab_routers(&fixture).await?;
    let admin = fixture.login("admin").await?;
    let links = nav_links(&text(fixture.get("/ui/r/home/dns", &admin).await?).await?);
    for (_slug, router_page) in ROUTER_PAGES {
        let expected = format!("/ui/r/home/{router_page}");
        assert!(links.contains(&expected), "{expected} in {links:?}");
    }
    every_link_lands(&fixture, &admin, &links).await?;
    let outsider = fixture.login("outsider").await?;
    let lab_links = nav_links(&text(fixture.get("/ui/r/lab-2/firewall", &outsider).await?).await?);
    for (_slug, router_page) in ROUTER_PAGES {
        let expected = format!("/ui/r/lab-2/{router_page}");
        assert!(lab_links.contains(&expected), "{expected} in {lab_links:?}");
    }
    every_link_lands(&fixture, &outsider, &lab_links).await?;
    lab_router.shutdown().await?;
    Ok(())
}

/// Without a router on the page, a role that reads several routers gets each section's
/// router picker, listing exactly the routers it may read.
#[tokio::test]
async fn a_page_without_a_router_opens_the_section_pickers() -> TestResult {
    let fixture = Fixture::new().await?;
    let (lab_router, _lab_dir) = add_lab_routers(&fixture).await?;
    let admin = fixture.login("admin").await?;
    let links = nav_links(&text(fixture.get("/ui/account", &admin).await?).await?);
    for (slug, router_page) in ROUTER_PAGES {
        let section = format!("/ui/{slug}");
        assert!(links.contains(&section), "{section} in {links:?}");
        let picker = open_ok(&fixture, &admin, &section).await?;
        for router in ["home", "lab-1", "lab-2"] {
            let link = format!("href=\"/ui/r/{router}/{router_page}\"");
            assert!(picker.contains(&link), "{link} on {section}: {picker}");
        }
    }
    every_link_lands(&fixture, &admin, &links).await?;
    let outsider = fixture.login("outsider").await?;
    for (slug, router_page) in ROUTER_PAGES {
        let picker = open_ok(&fixture, &outsider, &format!("/ui/{slug}")).await?;
        for router in ["lab-1", "lab-2"] {
            let link = format!("href=\"/ui/r/{router}/{router_page}\"");
            assert!(picker.contains(&link), "{link} on /ui/{slug}: {picker}");
        }
        assert!(
            !picker.contains("/ui/r/home"),
            "only the routers the role may read: {picker}"
        );
    }
    let scoped = nav_links(&text(fixture.get("/ui/account", &outsider).await?).await?);
    every_link_lands(&fixture, &outsider, &scoped).await?;
    lab_router.shutdown().await?;
    Ok(())
}

/// A role that reads exactly one router goes straight to that router's pages.
#[tokio::test]
async fn with_one_router_the_links_open_it() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let links = nav_links(&text(fixture.get("/ui/account", &admin).await?).await?);
    for (_slug, router_page) in ROUTER_PAGES {
        let expected = format!("/ui/r/home/{router_page}");
        assert!(links.contains(&expected), "{expected} in {links:?}");
    }
    every_link_lands(&fixture, &admin, &links).await?;
    Ok(())
}
