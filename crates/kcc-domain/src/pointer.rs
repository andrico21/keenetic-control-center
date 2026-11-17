//! JSON pointer segments built from router identifiers.

/// `token` as one JSON pointer segment: `~` becomes `~0` and `/` becomes `~1`.
pub(crate) fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}
