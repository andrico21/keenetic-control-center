//! The page as each role sees it.
//!
//! A router that can run Entware, one that asks for the MIPS installer and one that cannot
//! run it; the settings once Entware is set up; the localization and the escaping of what
//! the router reports.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::model::Model;

use super::{DRIVE, PAGE, model, over, ready};
use crate::support::{
    outcome::TestResult,
    page::{en, said, text},
};

/// An action of the page, as its control posts it.
fn posts(action: &str) -> String {
    format!("hx-post=\"{PAGE}/{action}")
}

/// Todo 12: the KN-1811 page shows the status to every role and the setup only to the
/// administrator, with the eligible drive and the internal storage but no installer choice.
#[tokio::test]
async fn kn1811_shows_the_status_and_the_setup_to_whom_may_run_it() -> TestResult {
    let fixture = over(model(Model::Kn1811)).await?;
    for (account, sets_up) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            format!("href=\"{PAGE}\""),
            en(keys::WEB_SYSTEM_ENTWARE_STATUS),
            en(keys::WEB_SYSTEM_ENTWARE_OPKG),
            en(keys::WEB_SYSTEM_ENTWARE_AVAILABLE),
            en(keys::WEB_SYSTEM_ENTWARE_ARCH_AARCH64),
            en(keys::WEB_SYSTEM_ENTWARE_NOT_SET),
            en(keys::WEB_SYSTEM_ENTWARE_SETUP_TITLE),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(&posts("setup")), sets_up, "{account} setup");
        assert_eq!(
            page.contains(&format!("name=\"drive\" value=\"{DRIVE}\"")),
            sets_up,
            "{account} drive"
        );
        assert_eq!(
            page.contains("name=\"drive\" value=\"internal\""),
            sets_up,
            "{account} internal storage"
        );
        assert_eq!(
            page.contains(&en(keys::WEB_SYSTEM_ENTWARE_INTERNAL_WARNING)),
            sets_up,
            "{account}: the router's warning beside the internal storage"
        );
        assert!(!page.contains("name=\"installer\""), "{account}: aarch64");
        assert!(
            !page.contains("bin.entware.net"),
            "{account}: no installer address"
        );
        assert!(!page.contains("https://"), "{account}: no address at all");
        for action in ["chroot", "timezone", "initrc", "dns-override", "remove"] {
            assert!(!page.contains(&posts(action)), "{account}: not set up");
        }
    }
    Ok(())
}

/// Todo 12: a router reporting `mips` asks for the installer, a select of the MIPS
/// installers of the closed table; no installer address is shown or editable.
#[tokio::test]
async fn a_mips_router_asks_for_the_installer() -> TestResult {
    let fixture = over(model(Model::Kn1010)).await?;
    let admin = fixture.login("admin").await?;
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    assert!(page.contains(&posts("setup")), "{page}");
    assert!(
        page.contains("<select class=\"field__input\" id=\"entware-installer\" name=\"installer\"")
    );
    for option in ["value=\"mipsel\"", "value=\"mips\""] {
        assert!(page.contains(option), "{option}");
    }
    assert!(page.contains(&en(keys::WEB_SYSTEM_ENTWARE_ARCH_MIPS)));
    assert!(!page.contains("bin.entware.net"), "no installer address");
    let viewer = fixture.login("viewer").await?;
    let read_only = text(fixture.get(PAGE, &viewer).await?).await?;
    assert!(
        !read_only.contains("name=\"installer\""),
        "the viewer sets nothing up"
    );
    Ok(())
}

/// Todo 12: a router without USB storage support says why and offers nothing, not even to
/// an administrator.
#[tokio::test]
async fn nc3013_says_why_and_offers_nothing() -> TestResult {
    let fixture = over(model(Model::Nc3013)).await?;
    let admin = fixture.login("admin").await?;
    let response = fixture.get(PAGE, &admin).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = text(response).await?;
    assert!(
        page.contains(&en(keys::WEB_SYSTEM_ENTWARE_NO_USB)),
        "{page}"
    );
    assert!(
        page.contains(&en(keys::WEB_SYSTEM_ENTWARE_NOT_INSTALLED)),
        "{page}"
    );
    assert!(
        !page.contains(&en(keys::WEB_SYSTEM_ENTWARE_AVAILABLE)),
        "no label promises the setup"
    );
    assert!(
        !page.contains(&format!("hx-post=\"{PAGE}")),
        "nothing offered"
    );
    assert!(!page.contains("name=\"drive\""), "no setup form");
    Ok(())
}

/// Todo 12: once `opkg disk` is set the page shows the settings and each role's actions.
///
/// The operator may change chroot, the time zone and DNS override, only the administrator
/// the startup script and the removal, the viewer nothing; DNS override carries the
/// household warning.
#[tokio::test]
async fn set_up_entware_shows_its_settings_and_the_role_s_actions() -> TestResult {
    let fixture = over(ready()).await?;
    for line in [
        "opkg disk fixture-media:/",
        "opkg initrc /opt/etc/init.d/rc.unslung",
        "opkg timezone Europe/Berlin",
    ] {
        assert!(fixture.handle().configure(line), "{line}");
    }
    let writes = ["chroot", "timezone", "dns-override"];
    let destructive = ["initrc", "remove"];
    for (account, writer, admin) in [
        ("viewer", false, false),
        ("operator", true, false),
        ("admin", true, true),
    ] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        for shown in [DRIVE, "/opt/etc/init.d/rc.unslung", "Europe/Berlin"] {
            assert!(page.contains(shown), "{account} misses {shown}");
        }
        for action in writes {
            assert_eq!(page.contains(&posts(action)), writer, "{account} {action}");
        }
        for action in destructive {
            assert_eq!(page.contains(&posts(action)), admin, "{account} {action}");
        }
        assert!(!page.contains(&posts("setup")), "{account}: already set up");
        assert!(
            !page.contains("bin.entware.net"),
            "{account}: no installer address"
        );
        assert!(!page.contains("https://"), "{account}: no address at all");
        assert_eq!(
            page.contains(&en(keys::WEB_SYSTEM_ENTWARE_DNS_WARNING)),
            writer,
            "{account}: the household warning beside DNS override"
        );
    }
    Ok(())
}

/// Todo 12: the page is localized: a Russian-speaking viewer reads it in Russian.
#[tokio::test]
async fn the_page_speaks_the_viewer_s_language() -> TestResult {
    let fixture = over(model(Model::Nc3013)).await?;
    let russian = fixture.login("russian").await?;
    let page = text(fixture.get(PAGE, &russian).await?).await?;
    for key in [
        keys::WEB_SYSTEM_ENTWARE_TITLE,
        keys::WEB_SYSTEM_ENTWARE_STATUS,
        keys::WEB_SYSTEM_ENTWARE_NO_USB,
        keys::WEB_SYSTEM_ENTWARE_OPKG,
    ] {
        assert!(
            page.contains(&said(Locale::Ru, key)),
            "{}: {page}",
            key.id()
        );
    }
    assert!(
        !page.contains(&en(keys::WEB_SYSTEM_ENTWARE_NO_USB)),
        "not English"
    );
    Ok(())
}

/// Todo 12: what the router reports is escaped: a hostile time zone and startup script
/// reach the page as text.
#[tokio::test]
async fn reported_settings_are_escaped() -> TestResult {
    let fixture = over(ready()).await?;
    for line in [
        "opkg disk fixture-media:/",
        "opkg initrc /opt/<script>x</script>",
        "opkg timezone <img/onerror=y>",
    ] {
        assert!(fixture.handle().configure(line), "{line}");
    }
    let admin = fixture.login("admin").await?;
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    assert!(
        !page.contains("<script>x") && !page.contains("<img/"),
        "{page}"
    );
    assert!(
        page.contains("&#60;script&#62;x&#60;/script&#62;"),
        "{page}"
    );
    assert!(page.contains("&#60;img/onerror=y&#62;"), "{page}");
    Ok(())
}

/// Todo 12: the drive list names each eligible drive with its medium and filesystem.
#[tokio::test]
async fn drives_name_their_medium_and_filesystem() -> TestResult {
    let fixture = over(model(Model::Kn1811)).await?;
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get(PAGE, &viewer).await?).await?;
    assert!(page.contains("Media0, ext4, "), "{page}");
    assert!(page.contains(&en(keys::WEB_SYSTEM_ENTWARE_PREPARE_NOTE)));
    assert!(page.contains("href=\"/ui/r/home/system/storage\""));
    Ok(())
}
