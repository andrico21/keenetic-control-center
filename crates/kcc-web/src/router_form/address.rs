//! The address and the id a router form accepts.

use url::Url;

/// An `http`/`https` origin with a host and no path, query or fragment.
pub(super) fn origin(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    let valid = matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    valid.then_some(url)
}

/// Whether `id` is a registry slug: 1 to 32 of `a-z`, `0-9` and `-`.
pub(crate) fn is_slug(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
