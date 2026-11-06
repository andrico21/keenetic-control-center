//! Unit tests of the clients view: a region read back keeps the page's view.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use core::error::Error;

use axum::http::Uri;
use kcc_domain::clients::Client;
use kcc_i18n::locale::Locale;

use super::{Filters, View};
use crate::clients_pages::client_rows::ClientRow;

/// A client with `mac`, connected when `up`, on Wi-Fi when it has a signal.
fn client(mac: &str, up: bool, rssi: Option<i16>) -> Client {
    let mut client = Client::default();
    client.mac = Some(mac.to_owned());
    client.link = up.then(|| "up".to_owned());
    client.rssi = rssi;
    client
}

#[test]
fn a_region_read_back_keeps_the_view_of_the_page() -> Result<(), Box<dyn Error>> {
    let page: Uri =
        "http://127.0.0.1:8080/ui/r/home/clients?q=10&state=online&link=wired&sort=mac&dir=desc"
            .parse()?;
    let clients = vec![
        client("02:00:00:00:10:01", true, None),
        client("02:00:00:00:10:02", false, None),
        client("02:00:00:00:10:03", true, Some(-40)),
        client("02:00:00:00:10:04", true, None),
        client("02:00:00:00:20:01", true, None),
    ];
    let region = View::of_page(Some(&page)).region(Locale::En, "home".to_owned(), clients);
    let shown: Vec<&str> = region.table.rows().iter().map(ClientRow::mac).collect();
    assert_eq!(
        shown,
        ["02:00:00:00:10:04", "02:00:00:00:10:01"],
        "online, wired, matching, highest MAC first"
    );
    assert_eq!(
        region.header("name").href(),
        "/ui/r/home/clients?q=10&state=online&link=wired&sort=name&dir=asc",
        "a sort link keeps every filter"
    );
    assert_eq!(
        region.pager().kept,
        "&state=online&link=wired",
        "so do pages"
    );
    assert_eq!(View::of_page(None).filters, Filters::default(), "no page");
    Ok(())
}
