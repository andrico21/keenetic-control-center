//! How the caller of a request signed in, read from the kit's identity on the HTTP
//! request, the account a kcc token speaks for, and the audit name that follows from it.
//!
//! Identities are namespaced so that no sign-in method can pass for another: an API key
//! keeps its name, a client certificate is `mtls:<cn>`, a kcc account token is
//! `oauth:<account>`, another identity provider's token is `oidc:<name>`, stdio is
//! `stdio`. Only an API-key caller marks a key used.

extern crate alloc;

use alloc::sync::Arc;

use http::request::Parts;
use kcc_app::{mcp_auth::verify::grant_id, permissions::KCC_ACCOUNT_ROLE};
use rmcp::service::{RequestContext, RoleServer};
use rmcp_server_kit::{
    auth::{AuthIdentity, AuthMethod},
    rbac::{current_identity, current_role, current_sub, current_token},
};
use tokio::task::spawn_blocking;

use crate::principals::{McpPrincipals, PrincipalRefusal};

/// How the request the current task serves signed in.
#[derive(Debug, Clone)]
struct Caller {
    /// The kit's sign-in method; `None` without an HTTP identity (stdio).
    method: Option<AuthMethod>,
    /// For a kcc account token: the account's current role name, or why it has none.
    account: Option<Result<String, PrincipalRefusal>>,
}

tokio::task_local! {
    /// The caller of the request the current task serves.
    static CALLER: Caller;
}

/// The sign-in method of the HTTP request `context` carries; `None` without one (stdio).
pub(crate) fn of_request(context: &RequestContext<RoleServer>) -> Option<AuthMethod> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AuthIdentity>())
        .map(|identity| identity.method)
}

/// Whether the request carries a kcc account token: the kit mapped its scope to the
/// reserved role, which no API key, certificate or other provider's token can hold.
pub(crate) fn is_kcc_account() -> bool {
    current_role().as_deref() == Some(KCC_ACCOUNT_ROLE)
}

/// Runs `work` as a request signed in with `method`; for a kcc account token the account
/// is resolved first, through `principals`, at the time of this request.
// cancel-safe: the resolution only reads; `work`'s own contract applies.
pub(crate) async fn scoped<F>(
    principals: Option<Arc<dyn McpPrincipals>>,
    method: Option<AuthMethod>,
    work: F,
) -> F::Output
where
    F: Future,
{
    let account = if is_kcc_account() {
        Some(resolve(principals).await)
    } else {
        None
    };
    CALLER.scope(Caller { method, account }, work).await
}

/// The current role name of the account behind this request's kcc token.
///
/// # Errors
///
/// [`PrincipalRefusal`] when the token names no account or grant, no resolver is
/// attached, or the account or grant does not stand.
///
/// `grant_id` reads the token's payload without checking its signature: that is sound
/// only because the kit verified the token (signature, issuer, audience, expiry) before
/// the request reached this handler, and `current_token` is that verified token.
// cancel-safe: the resolution runs to completion on its own thread; dropping this only
// stops waiting for it.
async fn resolve(principals: Option<Arc<dyn McpPrincipals>>) -> Result<String, PrincipalRefusal> {
    let resolver = principals.ok_or(PrincipalRefusal::Unavailable)?;
    let grant = current_token()
        .as_ref()
        .and_then(grant_id)
        .ok_or(PrincipalRefusal::Unavailable)?;
    let account = current_sub().ok_or(PrincipalRefusal::Unavailable)?;
    spawn_blocking(move || resolver.resolve(&account, &grant))
        .await
        .unwrap_or(Err(PrincipalRefusal::Unavailable))
}

/// The kcc account's role name, as resolved when the request started.
///
/// `None` outside a request scope, which refuses the caller.
pub(crate) fn account_role() -> Option<Result<String, PrincipalRefusal>> {
    CALLER
        .try_with(|caller| caller.account.clone())
        .ok()
        .flatten()
}

/// The sign-in method of the request the current task serves.
fn method() -> Option<AuthMethod> {
    CALLER.try_with(|caller| caller.method).ok().flatten()
}

/// The caller's name in the audit log and the workflow.
///
/// `mtls:<cn>` for a client certificate, `oauth:<account>` for a kcc account token,
/// `oidc:<name>` for another provider's token, the key name for an API key, `stdio`
/// without an HTTP identity.
pub(crate) fn name() -> String {
    let Some(identity) = current_identity() else {
        return "stdio".to_owned();
    };
    let account = is_kcc_account().then(current_sub).flatten();
    named(method(), account, identity)
}

/// `identity` namespaced by its sign-in `method`; `account` is the subject of a kcc
/// account token.
fn named(method: Option<AuthMethod>, account: Option<String>, identity: String) -> String {
    match (method, account) {
        (Some(AuthMethod::MtlsCertificate), _) => format!("mtls:{identity}"),
        (Some(AuthMethod::OAuthJwt), Some(subject)) => format!("oauth:{subject}"),
        (Some(AuthMethod::OAuthJwt), None) => format!("oidc:{identity}"),
        (Some(AuthMethod::BearerToken | _) | None, _) => identity,
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
            named(Some(AuthMethod::MtlsCertificate), None, name()),
            "mtls:laptop"
        );
        assert_eq!(named(Some(AuthMethod::BearerToken), None, name()), "laptop");
    }

    /// Regression (todo 31): a kcc account token is audited as `oauth:<account>` and
    /// another provider's token as `oidc:<name>`, so neither passes for an API key or a
    /// certificate of the same name.
    #[test]
    fn oauth_identities_are_namespaced_by_issuer() {
        let account = || Some("alice".to_owned());
        assert_eq!(
            named(Some(AuthMethod::OAuthJwt), account(), "alice".to_owned()),
            "oauth:alice"
        );
        assert_eq!(
            named(Some(AuthMethod::OAuthJwt), None, "alice".to_owned()),
            "oidc:alice"
        );
        assert_eq!(
            named(Some(AuthMethod::BearerToken), account(), "alice".to_owned()),
            "alice"
        );
    }
}
