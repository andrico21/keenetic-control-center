//! The redirect URI rules and the loopback match.

use core::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use super::{MAX_REDIRECT_URI_CHARS, RedirectRefusal};

/// Why `uri` cannot be registered; `None` when it can.
pub(super) fn redirect_refusal(uri: &str) -> Option<RedirectRefusal> {
    if uri.chars().count() > MAX_REDIRECT_URI_CHARS {
        return Some(RedirectRefusal::TooLong);
    }
    if !uri
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return Some(RedirectRefusal::Characters);
    }
    if uri.contains('*') {
        return Some(RedirectRefusal::Wildcard);
    }
    if uri.contains('#') {
        return Some(RedirectRefusal::Fragment);
    }
    let Ok(url) = Url::parse(uri) else {
        return Some(RedirectRefusal::Unparsable);
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Some(RedirectRefusal::UserInfo);
    }
    match url.scheme() {
        "https" => None,
        "http" => (!is_loopback(&url)).then_some(RedirectRefusal::PlainHttp),
        scheme => (!is_reverse_domain(scheme)).then_some(RedirectRefusal::Scheme),
    }
}

/// Whether `url`'s host is `127.0.0.1`, `[::1]` or `localhost`.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(address)) => address == Ipv6Addr::LOCALHOST,
        Some(Host::Domain(name)) => name == "localhost",
        None => false,
    }
}

/// Whether `scheme` is a domain name in reverse order: two or more non-empty labels of
/// lowercase letters, digits and `-`.
fn is_reverse_domain(scheme: &str) -> bool {
    scheme.contains('.')
        && scheme.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Whether `registered` and `requested` are loopback `http` URIs equal but for the port.
pub(super) fn same_loopback(registered: &str, requested: &str) -> bool {
    if redirect_refusal(requested).is_some() {
        return false;
    }
    let (Ok(stored), Ok(mut asked)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    stored.scheme() == "http"
        && is_loopback(&stored)
        && asked.set_port(stored.port()).is_ok()
        && asked == stored
}
