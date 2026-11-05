//! The Web UI Content-Security-Policy and the rmcp-server-kit security-header settings.
//!
//! The kit's security-header layer is the outermost response layer, so it decides the
//! final value of every header it manages, on MCP and Web UI responses alike.

use rmcp_server_kit::transport::SecurityHeadersConfig;

/// The policy for every response: same-origin scripts, styles, images, fonts, fetches
/// and form targets only; no inline script or style, no `eval`, no framing, no plugins.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; \
    frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

/// The Content-Security-Policy for the Web UI.
///
/// `upgrade-insecure-requests` is added only when the listener serves TLS: on a plain-HTTP
/// loopback deployment it would make the browser request every asset over `https` and
/// break the page, which is why the kit's default policy cannot be used.
#[inline]
#[must_use]
pub fn policy(tls: bool) -> String {
    if tls {
        format!("{POLICY}; upgrade-insecure-requests")
    } else {
        POLICY.to_owned()
    }
}

/// The kit's security-header configuration for a server that mounts the Web UI.
///
/// Sets the [`policy`] and omits the kit's `Cache-Control`: the kit inserts that header
/// on every response, which would replace the immutable policy of hash-addressed assets.
/// The web router sets `Cache-Control: no-store, max-age=0` on every other response
/// itself. Kit routes (`/mcp`, health, version) then carry no `Cache-Control`; they are
/// authenticated `POST` exchanges, event streams and small status documents without
/// validators, which neither browsers nor shared caches store or reuse. Every other kit
/// default (HSTS under TLS, `nosniff`, `X-Frame-Options`, referrer and cross-origin
/// policies) stays in place.
#[inline]
#[must_use]
pub fn security_headers(tls: bool) -> SecurityHeadersConfig {
    let mut headers = SecurityHeadersConfig::default();
    headers.content_security_policy = Some(policy(tls));
    headers.cache_control = Some(String::new());
    headers
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{policy, security_headers};

    #[test]
    fn plain_http_policy_has_no_upgrade() {
        let plain = policy(false);
        assert_eq!(
            plain,
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'",
            "exact policy"
        );
        assert!(
            !plain.contains("unsafe-"),
            "no unsafe-inline or unsafe-eval"
        );
    }

    #[test]
    fn tls_policy_upgrades_insecure_requests() {
        assert_eq!(
            policy(true),
            format!("{}; upgrade-insecure-requests", policy(false)),
            "TLS appends the directive"
        );
    }

    #[test]
    fn kit_headers_carry_the_policy_and_omit_cache_control() {
        let headers = security_headers(true);
        assert_eq!(
            headers.content_security_policy,
            Some(policy(true)),
            "policy"
        );
        assert_eq!(
            headers.cache_control.as_deref(),
            Some(""),
            "the empty value tells the kit to omit Cache-Control"
        );
        assert_eq!(
            headers.strict_transport_security, None,
            "HSTS keeps the kit default"
        );
    }
}
