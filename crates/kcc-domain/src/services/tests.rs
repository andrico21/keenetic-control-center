//! Which HTTP TLS settings cut kcc off from the listener its profile URL uses.

use core::str::FromStr as _;

use kcc_rci::RouterUrl;

use super::{HttpSslSetting, cuts_own_listener};

/// C-12: HTTP TLS settings that cut kcc off from its own listener are refused.
///
/// Over HTTPS, closing the TLS listener or moving it off the URL's port; over plain HTTP,
/// redirecting to HTTPS. Every other setting plans.
#[test]
fn settings_that_close_move_or_redirect_the_own_listener_are_refused() {
    for (url, setting, expected) in [
        (
            "https://router.invalid",
            HttpSslSetting::Enable(false),
            true,
        ),
        (
            "https://router.invalid",
            HttpSslSetting::Enable(true),
            false,
        ),
        ("https://router.invalid", HttpSslSetting::Port(443), false),
        ("https://router.invalid", HttpSslSetting::Port(8_443), true),
        (
            "https://router.invalid:8443",
            HttpSslSetting::Port(8_443),
            false,
        ),
        (
            "https://router.invalid",
            HttpSslSetting::Redirect(true),
            false,
        ),
        (
            "http://203.0.113.1:8080",
            HttpSslSetting::Redirect(true),
            true,
        ),
        (
            "http://203.0.113.1:8080",
            HttpSslSetting::Redirect(false),
            false,
        ),
        (
            "http://203.0.113.1:8080",
            HttpSslSetting::Enable(false),
            false,
        ),
        (
            "http://203.0.113.1:8080",
            HttpSslSetting::Port(8_080),
            false,
        ),
        ("https://router.invalid", HttpSslSetting::AcmeRevoke, false),
    ] {
        let cuts = RouterUrl::from_str(url)
            .ok()
            .map(|origin| cuts_own_listener(&origin, setting));
        assert_eq!(cuts, Some(expected), "{url} {setting:?}");
    }
}
