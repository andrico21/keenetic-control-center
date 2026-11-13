//! Navigation: every side-navigation link opens its section's page.
//!
//! On a router's page the section links open that router's pages; on a page without a
//! router they open the only router the role may read, or the section's router picker,
//! which lists only the routers the role may read. The sign-in page has a bare shell.

#[expect(
    dead_code,
    reason = "the shared explorer fixture; this suite needs only part of it"
)]
#[path = "explorer_pages/support.rs"]
mod support;

use core::net::SocketAddr;

use axum::http::StatusCode;
use kcc_app::{permissions::built_in_roles, registry::ManagedRouterProfile};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use tempfile::TempDir;
use url::Url;

use crate::support::{Browser, Fixture, TestResult, header_text, text};

/// The router page each router section opens, by section slug.
pub(crate) const ROUTER_PAGES: [(&str, &str); 8] = [
    ("clients", "clients"),
    ("network", "network"),
    ("wifi", "wifi"),
    ("routing", "routing"),
    ("firewall", "firewall"),
    ("dns", "dns"),
    ("vpn", "vpn"),
    ("system", "system/general"),
];

/// The side-navigation links of a page, in order.
pub(crate) fn nav_links(html: &str) -> Vec<String> {
    html.split("class=\"sidenav__link\" href=\"")
        .skip(1)
        .filter_map(|tail| tail.split_once('"').map(|(href, _)| href.to_owned()))
        .collect()
}

/// The one section the shared fixture cannot serve: it attaches no administration
/// services, so the Admin page answers its "not configured" page with 503.
const UNSERVED: &str = "/ui/admin";

/// Opens `path` as `browser`, following redirects: the address shown, its status and its
/// page.
///
/// # Errors
///
/// Fails when the page does not settle within four redirects.
pub(crate) async fn open(
    fixture: &Fixture,
    browser: &Browser,
    path: &str,
) -> TestResult<(String, StatusCode, String)> {
    let mut at = path.to_owned();
    for _hop in 0_u8..4 {
        let response = fixture.get(&at, browser).await?;
        if response.status().is_redirection() {
            at = header_text(&response, "location").ok_or("redirect without a location")?;
            continue;
        }
        let status = response.status();
        return Ok((at, status, text(response).await?));
    }
    Err(format!("{path} redirects too often").into())
}

/// Opens `path` as `browser`, which must answer 200: its page.
///
/// # Errors
///
/// Fails when the page does not answer 200.
pub(crate) async fn open_ok(
    fixture: &Fixture,
    browser: &Browser,
    path: &str,
) -> TestResult<String> {
    let (at, status, page) = open(fixture, browser, path).await?;
    if status != StatusCode::OK {
        return Err(format!("{path} (at {at}) answered {status}").into());
    }
    Ok(page)
}

/// Opens every navigation link of `page`: each answers 200 (but [`UNSERVED`]) with a page
/// of its own section.
///
/// # Errors
///
/// Fails when a section is missing, a link answers anything else, or its page marks
/// another section.
pub(crate) async fn every_link_lands(
    fixture: &Fixture,
    browser: &Browser,
    links: &[String],
) -> TestResult {
    if links.len() != 14 {
        return Err(format!("not every section is linked: {links:?}").into());
    }
    for link in links {
        let (at, status, shown) = open(fixture, browser, link).await?;
        let served = status == StatusCode::OK
            || (link == UNSERVED && status == StatusCode::SERVICE_UNAVAILABLE);
        if !served {
            return Err(format!("{link} (at {at}) answered {status}").into());
        }
        if !shown.contains(&format!("href=\"{link}\" aria-current=\"page\"")) {
            return Err(format!("{link} (at {at}) is not its section's page: {shown}").into());
        }
    }
    Ok(())
}

/// Registers `lab-1` and `lab-2` on a second fake router; keep both values alive.
///
/// # Errors
///
/// Fails when the fake router or the registry fails.
pub(crate) async fn add_lab_routers(fixture: &Fixture) -> TestResult<(Handle, TempDir)> {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let directory = TempDir::new()?;
    let password_file =
        kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let admin = built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("admin role")?;
    for id in ["lab-1", "lab-2"] {
        let profile = ManagedRouterProfile::new(
            id.to_owned(),
            Url::parse(&format!("http://{address}"))?,
            DEFAULT_LOGIN.to_owned(),
            password_file.clone(),
        );
        fixture.registry().create(&admin, profile).await?;
    }
    Ok((handle, directory))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "navigation/links.rs"]
mod links;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "navigation/shell.rs"]
mod shell;
