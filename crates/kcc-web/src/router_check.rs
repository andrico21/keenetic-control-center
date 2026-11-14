//! The connection test at `/ui/routers/test` and the outbound-policy check of the router
//! forms.

use core::{net::IpAddr, str::FromStr as _};
use std::path::PathBuf;

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::registry::{ManagedRouterProfile, ProfileSource, RegistryError};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::{
    RciError, RouterUrl, TlsMode,
    capabilities::{AuthSchemeKind, RouterInfo, SupportTier},
    outbound::{is_metadata_address, never_admitted},
    session::HttpTimeouts,
};
use url::Url;

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    fleet::Fleet,
    page::{Localize as _, Shell, Theme},
    page_kit::{audit::Record, context::managed},
    router_form::{FieldErrors, RouterForm, address::is_slug},
};

/// The id a connection test uses when the form has no valid one yet.
const TEST_ID: &str = "connection-test";

/// `POST /ui/routers/test`: tests a stored profile or signs in with typed credentials.
///
/// An empty password on the edit form uses the stored one. A failure, including an
/// outbound-policy refusal, is explained in the viewer's language.
pub(crate) async fn test(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(form): Form<RouterForm>,
) -> Response {
    let shell = Shell::new(user.locale(), Theme::System);
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let editing = form.router().to_owned();
    let draft_id = form.id().to_owned();
    let (_draft, typed, parsed) = form.parse(user.locale(), false);
    let password = typed.into_password();
    let id = if password.is_some() {
        is_slug(&draft_id).then_some(draft_id.as_str())
    } else {
        is_slug(&editing).then_some(editing.as_str())
    }
    .unwrap_or(TEST_ID)
    .to_owned();
    let audit = Record::on_router("web.router_test", &id, String::new());
    let fields = match parsed {
        Ok(fields) => fields,
        Err(errors) => {
            audit.append(&state, &user, "refused").await;
            return errors::render(&TestResult::invalid(shell, &errors));
        }
    };
    let mut profile =
        ManagedRouterProfile::new(id, fields.url().clone(), String::new(), PathBuf::new());
    fields.apply(&mut profile);
    let outcome = if let Some(secret) = password {
        fleet
            .registry()
            .test_connection_with(&profile, secret)
            .await
    } else {
        if !draft_id.is_empty() && draft_id != editing {
            audit.append(&state, &user, "refused").await;
            let refused = TestResult::message(shell, keys::WEB_ROUTER_ERROR_ID);
            return errors::render(&refused);
        }
        let Ok(existing) = managed(fleet, user.role(), &editing).await else {
            audit.append(&state, &user, "refused").await;
            let missing = TestResult::message(shell, keys::WEB_ROUTER_ERROR_PASSWORD);
            return errors::render(&missing);
        };
        if !matches!(existing.source, ProfileSource::State) {
            audit.append(&state, &user, "refused").await;
            let refused = TestResult::message(shell, keys::WEB_ROUTER_CONFIG_DEFINED);
            return errors::render(&refused);
        }
        profile = existing.profile;
        fleet.registry().test_connection(&profile).await
    };
    let audit_outcome = if outcome.is_ok() { "success" } else { "failed" };
    audit.append(&state, &user, audit_outcome).await;
    errors::render(&TestResult::new(shell, &outcome, &profile.url))
}

/// Whether the outbound policy admits `url`; resolves the host but sends nothing.
// cancel-safe: resolution changes no state.
pub(crate) async fn allowed(fleet: &Fleet, url: &Url) -> bool {
    let Ok(target) = RouterUrl::from_str(url.as_str()) else {
        return false;
    };
    fleet
        .registry()
        .outbound_policy()
        .client_builder(&target, &TlsMode::Verify, HttpTimeouts::default())
        .await
        .is_ok()
}

/// Why the outbound policy refuses a router at `url`, in `locale`: the
/// `[outbound] allowed_networks` setting to change and the router's address, or, for a
/// cloud metadata address, that it is always refused.
pub(crate) fn policy_refusal(locale: Locale, url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    let literal = host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(|address| address.to_canonical());
    if literal.is_some_and(is_metadata_address) {
        return tr(locale, keys::WEB_ROUTER_ERROR_POLICY, None);
    }
    let mut args = FluentArgs::new();
    args.set("address", host.to_owned());
    let key = match literal {
        Some(address) if address.is_loopback() => keys::ERRORS_OUTBOUND_LOOPBACK,
        Some(address) if never_admitted(address) => keys::ERRORS_OUTBOUND_NEVER,
        Some(_) | None => keys::ERRORS_OUTBOUND_REFUSED,
    };
    tr(locale, key, Some(&args))
}

/// The outcome of a connection test.
#[derive(Template)]
#[template(path = "partials/test_result.html")]
pub(crate) struct TestResult {
    /// Locale carrier.
    shell: Shell,
    /// The localized failure, or empty on success.
    error: String,
    /// Detected model and hardware id.
    model: String,
    /// Detected firmware.
    firmware: String,
    /// Support tier label.
    tier: MessageKey,
    /// Advertised sign-in schemes.
    schemes: String,
}

impl TestResult {
    /// The result of `outcome` for the router at `url`, described in the shell's locale.
    pub(crate) fn new(
        shell: Shell,
        outcome: &Result<RouterInfo, RegistryError>,
        url: &Url,
    ) -> Self {
        let locale = shell.locale();
        match outcome {
            Ok(info) => Self {
                shell,
                error: String::new(),
                model: [info.version.model.as_deref(), info.hw_id()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
                firmware: info
                    .firmware
                    .map(|firmware| firmware.to_string())
                    .unwrap_or_default(),
                tier: match info.support_tier() {
                    SupportTier::HardwareVerified => keys::WEB_TIER_VERIFIED,
                    SupportTier::DocumentationBased => keys::WEB_TIER_DOCUMENTATION,
                    SupportTier::Unsupported | _ => keys::WEB_TIER_UNSUPPORTED,
                },
                schemes: info
                    .auth_schemes
                    .iter()
                    .map(|scheme| match scheme {
                        AuthSchemeKind::Ndw2 => "ndw2".to_owned(),
                        AuthSchemeKind::Ndw4 => "ndw4".to_owned(),
                        AuthSchemeKind::Other(name) => name.clone(),
                        _ => String::new(),
                    })
                    .filter(|name| !name.is_empty())
                    .collect::<Vec<_>>()
                    .join(", "),
            },
            Err(RegistryError::Rci(RciError::Policy)) => {
                Self::failed(shell, policy_refusal(locale, url))
            }
            Err(RegistryError::CredentialPermissions { path }) => {
                let mut args = FluentArgs::new();
                args.set("path", path.display().to_string());
                let error = tr(locale, keys::ERRORS_SECRET_FILE_PERMISSIONS, Some(&args));
                Self::failed(shell, error)
            }
            Err(error) => Self::failed(shell, tr(locale, failure(error), None)),
        }
    }

    /// A test that could not run because the form is invalid.
    pub(crate) fn invalid(shell: Shell, errors: &FieldErrors) -> Self {
        let error = errors.first().to_owned();
        Self::failed(shell, error)
    }

    /// A test that could not run, explained by `key`.
    pub(crate) fn message(shell: Shell, key: MessageKey) -> Self {
        let error = tr(shell.locale(), key, None);
        Self::failed(shell, error)
    }

    /// A failed test showing `error`.
    const fn failed(shell: Shell, error: String) -> Self {
        Self {
            shell,
            error,
            model: String::new(),
            firmware: String::new(),
            tier: keys::WEB_TIER_UNSUPPORTED,
            schemes: String::new(),
        }
    }
}

localized!(TestResult);

/// The message explaining why a connection test failed.
pub(crate) const fn failure(error: &RegistryError) -> MessageKey {
    match error {
        RegistryError::Rci(RciError::Policy) => keys::WEB_ROUTER_ERROR_POLICY,
        RegistryError::Rci(RciError::Auth(_)) => keys::ERRORS_ROUTER_AUTH,
        RegistryError::Rci(RciError::Transport | RciError::Timeout) => {
            keys::WEB_ROUTER_ERROR_UNREACHABLE
        }
        RegistryError::InvalidProfile { reason: _ } => keys::WEB_ROUTER_ERROR_URL,
        RegistryError::CredentialFile { path: _, source: _ } => keys::WEB_ROUTER_ERROR_PASSWORD,
        RegistryError::State(_)
        | RegistryError::PermissionDenied { router: _ }
        | RegistryError::AlreadyExists { id: _ }
        | RegistryError::NotFound { id: _ }
        | RegistryError::ConfigDefined { id: _ }
        | RegistryError::Rci(_)
        | _ => keys::WEB_ROUTER_ERROR_CHECK,
    }
}
