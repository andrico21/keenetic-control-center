//! The router id of a route-table path, percent-decoded as the handlers see it.

/// The router path parameter of a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RouterSegment {
    /// The percent-decoded router id, as the handlers' `Path` extractor sees it.
    Id(String),
    /// A segment that does not percent-decode to UTF-8; no handler accepts it.
    Undecodable,
}

/// Extracts the percent-decoded router id from the `/ui/r/{router}/...` and
/// `/ui/sse/r/{router}/...` route families.
pub(super) fn router_scope(path: &str) -> Option<RouterSegment> {
    let mut segments = path.trim_start_matches('/').split('/');
    let ((Some("ui"), Some("r"), Some(router), _)
    | (Some("ui"), Some("sse"), Some("r"), Some(router))) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    )
    else {
        return None;
    };
    (!router.is_empty())
        .then(|| percent_decoded(router).map_or(RouterSegment::Undecodable, RouterSegment::Id))
}

/// `segment` with every `%` and two hex digits replaced by that byte, as axum's `Path`
/// extractor decodes a path segment (`+` stays `+`, a `%` without two hex digits stays);
/// `None` when the bytes are not UTF-8.
fn percent_decoded(segment: &str) -> Option<String> {
    let hex = |byte: &u8| -> Option<u8> { u8::try_from(char::from(*byte).to_digit(16)?).ok() };
    let mut bytes = Vec::with_capacity(segment.len());
    let mut rest = segment.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        let escaped = match (first, tail) {
            (b'%', [high, low, after @ ..]) => hex(high).zip(hex(low)).map(|pair| (pair, after)),
            _ => None,
        };
        if let Some(((high, low), after)) = escaped {
            bytes.push(high.saturating_mul(16).saturating_add(low));
            rest = after;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};

    use crate::authz::permits;

    /// SEC1-14: the route table checks the router scope against the percent-decoded router
    /// id, the one the handlers' `Path` extractor sees.
    ///
    /// `%68ome` (any hex case) is `home`; a double encoding decodes once, to `%68ome`,
    /// which is not `home`; and a role whose scope glob is the literal text `%61` does
    /// not reach the router `a` through `/ui/r/%61/...`.
    #[test]
    fn router_scope_uses_the_decoded_router_id() {
        let scoped = |glob: &str| {
            Role::new(
                "scoped".to_owned(),
                [Permission::Read],
                vec![glob.to_owned()],
            )
        };
        let home = scoped("home");
        for path in [
            "/ui/r/%68ome/system",
            "/ui/r/h%6Fme/system",
            "/ui/r/h%6fme/system",
            "/ui/sse/r/%68%6F%6d%65/system/jobs/job-1",
        ] {
            assert!(permits(&home, path), "{path} is home");
        }
        for path in ["/ui/r/%2568ome/system", "/ui/r/%68omf/system"] {
            assert!(!permits(&home, path), "{path} is not home");
        }
        assert!(
            !permits(&scoped("%61"), "/ui/r/%61/system"),
            "the router a is outside the scope %61"
        );
        assert!(
            !permits(&scoped("*"), "/ui/r/%FF/system"),
            "a router id that does not decode is refused"
        );
    }
}
