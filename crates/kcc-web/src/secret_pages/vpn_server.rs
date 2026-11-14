//! The VPN servers' credentials: the IKE key of the IPsec/IKEv2 server, and the password
//! of a router account that signs in to the PPTP/L2TP, SSTP or OpenConnect server.
//!
//! An account's password is a management change, like on the router users page, and the
//! account kcc signs in with is refused before anything is sent.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::{
    RouterCtx, router_users,
    vpn_clients::secrets::{self, CredentialTarget},
    vpn_servers::{self, secrets as server_secrets},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::ObjectName;

use super::{
    dialog::{Entry, Plain, SecretDialog, entry, plain_value},
    reply::{unchanged, verified},
    user_password::{account, protected, run},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    page_kit::{
        action::Operation,
        change::Applied,
        confirm::Confirmation,
        failure::plan_failure,
        family::Family,
        respond::{Answer, changed},
    },
    system_pages::shared::profile_login,
};

/// Setting the IPsec server's IKE key, audited as `web.vpn_server_psk`.
const IKE_KEY: Operation =
    Operation::write(&vpn_servers::DESCRIPTOR, "ike_psk", "web.vpn_server_psk");

/// Setting a VPN account's password, audited as `web.vpn_server_password`.
const PASSWORD: Operation = Operation::write(
    &vpn_servers::DESCRIPTOR,
    "password",
    "web.vpn_server_password",
);

/// The IKE key dialog on `router`, its name field holding `key`.
fn key_dialog(router: &str, key: &str, locale: Locale) -> SecretDialog {
    SecretDialog::new(
        locale,
        (keys::WEB_SECRET_IKE_TITLE, ""),
        format!("/ui/r/{router}/vpn/server/psk"),
        (keys::WEB_SECRET_NEW_KEY, keys::WEB_SECRET_KEEP_HELP),
    )
    .intro(keys::WEB_SECRET_IKE_INTRO)
    .with_plain(Plain::new(
        locale,
        (
            "key",
            keys::WEB_SECRET_IKE_NAME,
            keys::WEB_SECRET_IKE_NAME_HELP,
        ),
        key,
    ))
}

/// The account password dialog on `router`, offering `accounts`, `chosen` selected.
fn password_dialog_for(
    router: &str,
    (accounts, chosen): (Vec<String>, &str),
    locale: Locale,
) -> SecretDialog {
    let dialog = SecretDialog::new(
        locale,
        (keys::WEB_SECRET_VPN_ACCOUNT_TITLE, ""),
        format!("/ui/r/{router}/vpn/server/password"),
        (keys::WEB_SECRET_NEW_PASSWORD, keys::WEB_SECRET_USER_HELP),
    )
    .intro(keys::WEB_SECRET_VPN_ACCOUNT_INTRO)
    .management();
    if accounts.is_empty() {
        return dialog.refused(tr(locale, keys::WEB_SECRET_VPN_NO_ACCOUNT, None));
    }
    let field = Plain::new(
        locale,
        (
            "account",
            keys::WEB_SECRET_ACCOUNT,
            keys::WEB_SECRET_ACCOUNT_HELP,
        ),
        chosen,
    );
    dialog.with_plain(field.choosing(accounts))
}

/// `GET /ui/r/{router}/vpn/server/psk`: the IKE key dialog; it never holds the stored key.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn psk_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = IKE_KEY.open(&state, &user, &router).await?;
    Ok(key_dialog(&router, "", action.locale()).show())
}

/// `POST /ui/r/{router}/vpn/server/psk`: sets the IKE key named in the form to the value
/// typed twice.
///
/// # Errors
///
/// Answers the dialog with its error (422), and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn psk(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = IKE_KEY.open(&state, &user, &router).await?;
    let locale = action.locale();
    let typed_key = plain_value(&form, "key");
    let shown = key_dialog(&router, &typed_key, locale);
    let secret = match entry(&mut form) {
        Entry::Keep => return Ok(unchanged(action).await),
        Entry::Mismatch => {
            action.abandon("validation_failed").await;
            return Err(shown.mismatch());
        }
        Entry::New(typed) => typed,
    };
    let Ok(key) = ObjectName::try_from(typed_key) else {
        action.abandon("validation_failed").await;
        return Err(shown.plain_error(tr(locale, keys::WEB_SECRET_IKE_NAME_ERROR, None)));
    };
    let domain = action.context().await?;
    let target = CredentialTarget::Ike(key.clone());
    if let Err(error) = secrets::plan(&domain, &target, secret.clone()) {
        let failure = plan_failure(Family::Changes, locale, &error);
        action.abandon(failure.audit()).await;
        return Err(shown.secret_error(failure.message().to_owned()));
    }
    let applied = action
        .run_with(Risk::Write, async move |changes, context| {
            server_secrets::apply_ike_psk(changes, context, key, secret)
                .await
                .map(|()| Applied::Done { unsaved: true })
        })
        .await;
    let outcome = verified(applied, locale, keys::WEB_VPN_PRESHARED);
    Ok(changed(outcome, None, None, locale))
}

/// The router accounts a VPN password may be set for: every account but the one kcc signs
/// in with.
///
/// # Errors
///
/// Answers the failure in the page's outcome region when the router cannot be read.
// cancel-safe: reads only.
async fn accounts(domain: &RouterCtx, login: &str, locale: Locale) -> Result<Vec<String>, Answer> {
    let users = router_users::read_users(domain)
        .await
        .map_err(|_error| unusable(locale, Family::Changes.unreachable()))?;
    Ok(users
        .into_iter()
        .filter_map(|user| user.name)
        .filter(|name| name != login)
        .collect())
}

/// `GET /ui/r/{router}/vpn/server/password`: the account password dialog, listing the
/// router accounts kcc may change.
///
/// # Errors
///
/// Answers the failure when the router cannot be read, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn password_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = PASSWORD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    let domain = action.context().await?;
    let offered = accounts(&domain, &login, locale).await?;
    let chosen = offered.first().cloned().unwrap_or_default();
    Ok(password_dialog_for(&router, (offered, &chosen), locale).show())
}

/// `POST /ui/r/{router}/vpn/server/password`: sets the password typed twice for the
/// account chosen in the form, confirmed by the dialog's Apply.
///
/// # Errors
///
/// Answers 404 for an unknown account, the dialog with its error or the refusal (422), and
/// what the kit answers when the router or the permission is missing.
pub(crate) async fn password(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = PASSWORD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let chosen = plain_value(&form, "account");
    let confirmed = Confirmation::from_pairs(&form).confirmed();
    let shown = password_dialog_for(&router, (vec![chosen.clone()], &chosen), locale);
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    if login == chosen {
        action.abandon("protected_account").await;
        return Err(shown.refused(protected(locale)).refusal());
    }
    let secret = match entry(&mut form) {
        Entry::Keep => return Ok(unchanged(action).await),
        Entry::Mismatch => {
            action.abandon("validation_failed").await;
            return Err(shown.mismatch());
        }
        Entry::New(typed) => typed,
    };
    let Ok(name) = ObjectName::try_from(chosen) else {
        action.abandon("validation_failed").await;
        return Err(shown.plain_error(tr(locale, keys::WEB_SYSTEM_USERS_NAME_ERROR, None)));
    };
    if !confirmed {
        action.abandon("confirmation_required").await;
        return Err(shown.secret_error(tr(locale, keys::WEB_SECRET_CONFIRM, None)));
    }
    let (known, domain) = account(action, name.as_str()).await?;
    let planned = server_secrets::plan_password(&domain, &name, &login, secret)
        .and_then(|operation| server_secrets::password_request(&operation));
    run(known, planned, shown).await
}
