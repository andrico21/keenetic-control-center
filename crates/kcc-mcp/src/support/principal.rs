//! How the caller of a request signed in, read from the kit's identity on the HTTP
//! request, and the audit name that follows from it.
//!
//! Identities are namespaced so that no sign-in method can pass for another: an API key
//! keeps its name, a client certificate is `mtls:<cn>`, stdio is `stdio`. Only an API-key
//! caller marks a key used.

use http::request::Parts;
use rmcp::service::{RequestContext, RoleServer};
use rmcp_server_kit::{
    auth::{AuthIdentity, AuthMethod},
    rbac::current_identity,
};

tokio::task_local! {
    /// The sign-in method of the request the current task serves.
    static METHOD: Option<AuthMethod>;
}

/// The sign-in method of the HTTP request `context` carries; `None` without one (stdio).
pub(crate) fn of_request(context: &RequestContext<RoleServer>) -> Option<AuthMethod> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AuthIdentity>())
        .map(|identity| identity.method)
}

/// Runs `work` as a request signed in with `method`.
// cancel-safe: only scopes `work`, whose own contract applies.
pub(crate) async fn scoped<F>(method: Option<AuthMethod>, work: F) -> F::Output
where
    F: Future,
{
    METHOD.scope(method, work).await
}

/// The sign-in method of the request the current task serves.
fn method() -> Option<AuthMethod> {
    METHOD.try_with(|method| *method).ok().flatten()
}

/// The caller's name in the audit log and the workflow: `mtls:<cn>` for a client
/// certificate, the key name for an API key, `stdio` without an HTTP identity.
pub(crate) fn name() -> String {
    let Some(identity) = current_identity() else {
        return "stdio".to_owned();
    };
    named(method(), identity)
}

/// `identity` namespaced by its sign-in `method`.
fn named(method: Option<AuthMethod>, identity: String) -> String {
    match method {
        Some(AuthMethod::MtlsCertificate) => format!("mtls:{identity}"),
        Some(AuthMethod::BearerToken | AuthMethod::OAuthJwt | _) | None => identity,
    }
}

/// Whether the caller signed in with an API key.
pub(crate) fn is_api_key() -> bool {
    method() == Some(AuthMethod::BearerToken)
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test code fails by panicking")]
mod tests {
    use rmcp_server_kit::auth::AuthMethod;

    use super::named;

    /// Regression (todo 28): a client certificate's name is namespaced `mtls:` in the audit
    /// log; an API key keeps its name, so a certificate named like a key never passes for it.
    #[test]
    fn a_certificate_name_is_namespaced_and_a_key_name_is_not() {
        let name = || "laptop".to_owned();
        assert_eq!(
            named(Some(AuthMethod::MtlsCertificate), name()),
            "mtls:laptop"
        );
        assert_eq!(named(Some(AuthMethod::BearerToken), name()), "laptop");
    }
}
