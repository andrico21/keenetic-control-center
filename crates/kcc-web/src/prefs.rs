//! Per-request display preferences: the `kcc_lang` and `kcc_theme` cookies and
//! `Accept-Language`.

use axum::http::{HeaderMap, header};
use kcc_i18n::locale::{self, Locale};

use crate::page::{Shell, Theme};

/// A page shell in the request's preferences: the locale from the `kcc_lang` cookie, then
/// `Accept-Language`, then `default_locale`; the theme from the `kcc_theme` cookie.
pub(crate) fn shell(headers: &HeaderMap, default_locale: Locale) -> Shell {
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    let locale = Locale::negotiate(
        None,
        cookie(headers, locale::COOKIE_NAME),
        accept_language,
        Some(default_locale),
    );
    let theme = cookie(headers, Theme::COOKIE_NAME).map_or(Theme::System, Theme::from_cookie);
    Shell::new(locale, theme)
}

/// The value of the first cookie named `name` across every `Cookie` header.
fn cookie<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
    use kcc_i18n::locale::Locale;

    use super::{cookie, shell};
    use crate::page::Theme;

    /// Headers holding each `(name, value)` pair.
    fn headers(pairs: &[(HeaderName, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let _: bool = map.append(name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn cookies_are_found_across_headers() {
        let map = headers(&[
            (header::COOKIE, "a=1; kcc_theme=dark"),
            (header::COOKIE, "kcc_lang=ru"),
        ]);
        assert_eq!(cookie(&map, "kcc_theme"), Some("dark"), "first header");
        assert_eq!(cookie(&map, "kcc_lang"), Some("ru"), "second header");
        assert_eq!(cookie(&map, "kcc"), None, "names are exact");
        assert_eq!(shell(&map, Locale::En).theme(), Theme::Dark, "theme cookie");
    }

    #[test]
    fn cookie_beats_accept_language_beats_default() {
        let both = headers(&[
            (header::COOKIE, "kcc_lang=uk"),
            (header::ACCEPT_LANGUAGE, "de"),
        ]);
        assert_eq!(shell(&both, Locale::Kk).locale(), Locale::Uk, "cookie");
        let accept = headers(&[(header::ACCEPT_LANGUAGE, "be-BY,ru;q=0.5")]);
        assert_eq!(
            shell(&accept, Locale::Kk).locale(),
            Locale::Be,
            "Accept-Language"
        );
        let none = shell(&HeaderMap::new(), Locale::Kk);
        assert_eq!(none.locale(), Locale::Kk, "default");
        assert_eq!(none.theme(), Theme::System, "no theme cookie");
    }
}
