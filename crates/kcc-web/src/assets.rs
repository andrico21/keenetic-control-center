//! Embedded static assets, addressed by content hash.
//!
//! Every file is embedded at build time and served from
//! `/ui/static/<first 16 hex digits of its SHA-256>/<file name>` with an immutable cache
//! policy, so a changed file always gets a new URL. Templates reference assets by their
//! path under `assets/` through the `stylesheet` and `script` macros, which also emit the
//! Subresource Integrity value. Vendored files are pinned in `assets/ASSETS.lock` and
//! checked by `cargo xtask assets-check`.

use std::sync::LazyLock;

use axum::{
    extract::{Path, State, rejection::PathRejection},
    http::{HeaderMap, header},
    response::{IntoResponse as _, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

use crate::{
    WebState,
    errors::{self, Kind},
    prefs,
};

/// Route of every static asset.
pub(crate) const ROUTE: &str = "/ui/static/{digest}/{file}";

/// Number of hexadecimal digest digits in an asset URL.
const DIGEST_DIGITS: usize = 16;

/// `Cache-Control` of a hash-addressed asset: its content never changes.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Content-Type` of stylesheets.
const CSS: &str = "text/css; charset=utf-8";

/// `Content-Type` of scripts.
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";

/// An embedded file: its path under `assets/`, its content type and its bytes.
type Source = (&'static str, &'static str, &'static [u8]);

/// Every embedded file.
const SOURCES: [Source; 6] = [
    ("css/app.css", CSS, include_bytes!("../assets/css/app.css")),
    (
        "js/app.js",
        JAVASCRIPT,
        include_bytes!("../assets/js/app.js"),
    ),
    (
        "vendor/htmx.min.js",
        JAVASCRIPT,
        include_bytes!("../assets/vendor/htmx.min.js"),
    ),
    (
        "vendor/htmx-ext-sse.min.js",
        JAVASCRIPT,
        include_bytes!("../assets/vendor/htmx-ext-sse.min.js"),
    ),
    (
        "vendor/uPlot.iife.min.js",
        JAVASCRIPT,
        include_bytes!("../assets/vendor/uPlot.iife.min.js"),
    ),
    (
        "vendor/uPlot.min.css",
        CSS,
        include_bytes!("../assets/vendor/uPlot.min.css"),
    ),
];

/// Every embedded asset with its address and integrity value, computed on first use.
static ASSETS: LazyLock<Vec<Asset>> = LazyLock::new(|| SOURCES.iter().map(Asset::new).collect());

/// One embedded asset.
#[derive(Debug)]
pub(crate) struct Asset {
    /// Path under `assets/`, for example `vendor/htmx.min.js`.
    path: &'static str,
    /// File name, the last URL segment.
    file: &'static str,
    /// `Content-Type` header value.
    content_type: &'static str,
    /// File contents.
    bytes: &'static [u8],
    /// Hexadecimal SHA-256 prefix, the second-to-last URL segment.
    digest: String,
    /// `/ui/static/<digest>/<file>`.
    url: String,
    /// Subresource Integrity value, `sha256-<base64>`.
    integrity: String,
}

impl Asset {
    /// Hashes `source` and derives its URL and integrity value.
    fn new(&(path, content_type, bytes): &Source) -> Self {
        let hash = Sha256::digest(bytes);
        let mut digest = hex(&hash);
        digest.truncate(DIGEST_DIGITS);
        let file = path.rsplit('/').next().unwrap_or(path);
        Self {
            path,
            file,
            content_type,
            bytes,
            url: format!("/ui/static/{digest}/{file}"),
            integrity: format!("sha256-{}", STANDARD.encode(hash)),
            digest,
        }
    }

    /// `/ui/static/<digest>/<file>`.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Subresource Integrity value for the `integrity` attribute.
    pub(crate) fn integrity(&self) -> &str {
        &self.integrity
    }
}

/// The asset at `path` under `assets/`, as named in templates.
pub(crate) fn find(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|asset| asset.path == path)
}

/// Serves the asset addressed by the URL, or the 404 page.
// cancel-safe: it has no await point.
pub(crate) async fn serve(
    State(state): State<WebState>,
    address: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let found = address.ok().and_then(|Path((digest, file))| {
        ASSETS
            .iter()
            .find(|asset| asset.digest == digest && asset.file == file)
    });
    found.map_or_else(
        || {
            errors::response(
                Kind::NotFound,
                prefs::shell(&headers, state.default_locale()),
            )
        },
        |asset| {
            (
                [
                    (header::CONTENT_TYPE, asset.content_type),
                    (header::CACHE_CONTROL, IMMUTABLE),
                ],
                asset.bytes,
            )
                .into_response()
        },
    )
}

/// Lowercase hexadecimal encoding of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4_u8, byte & 0x0f] {
            if let Some(digit) = char::from_digit(u32::from(nibble), 16) {
                text.push(digit);
            }
        }
    }
    text
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{ASSETS, SOURCES, find, hex};

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(
            hex(&[0x00, 0x0f, 0xa0, 0xff]),
            "000fa0ff",
            "two digits per byte"
        );
    }

    #[test]
    fn every_source_has_a_hash_address() {
        assert_eq!(ASSETS.len(), SOURCES.len(), "one asset per source");
        for asset in ASSETS.iter() {
            assert_eq!(asset.digest.len(), 16, "{}", asset.path);
            assert_eq!(
                asset.url(),
                format!("/ui/static/{}/{}", asset.digest, asset.file),
                "{}",
                asset.path
            );
            assert!(
                asset.integrity().starts_with("sha256-") && asset.integrity().len() == 51,
                "{}",
                asset.integrity()
            );
            assert!(!asset.bytes.is_empty(), "{}", asset.path);
        }
        assert_eq!(
            find("vendor/htmx.min.js").map(|asset| asset.file),
            Some("htmx.min.js"),
            "lookup by path"
        );
        assert!(find("vendor/missing.js").is_none(), "unknown path");
    }
}
