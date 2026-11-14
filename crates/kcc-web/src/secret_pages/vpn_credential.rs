//! A VPN client's credential: the password of an L2TP/IPsec, PPTP or SSTP connection, the
//! IPsec pre-shared key of an L2TP/IPsec connection, and the pre-shared key and `XAuth`
//! password of an IPsec profile.
//!
//! The VPN client domain writes it and reads the running configuration back for a stored
//! value of a plausible length, never decoding it.

use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::vpn_clients::{
    self, VpnClientStatus, VpnClientType,
    secrets::{self, CredentialTarget},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use kcc_rci::ObjectName;

use super::{
    dialog::{Entry, SecretDialog, entry},
    reply::{unchanged, verified},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    page_kit::{
        action::Operation,
        change::Applied,
        failure::plan_failure,
        family::Family,
        request::{Params, missing, with_query},
        respond::{Answer, changed},
    },
};

/// Which credential a dialog sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The PPP password of an L2TP/IPsec, PPTP or SSTP connection.
    Password,
    /// The IPsec pre-shared key of an L2TP/IPsec connection.
    Ipsec,
    /// The pre-shared key of an IPsec profile.
    ProfileKey,
    /// The `XAuth` password of an IPsec profile.
    Xauth,
}

impl Kind {
    /// Every kind.
    const ALL: [Self; 4] = [Self::Password, Self::Ipsec, Self::ProfileKey, Self::Xauth];

    /// The kind named by the query value `slug`.
    fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.slug() == slug)
    }

    /// The query value.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Ipsec => "ipsec",
            Self::ProfileKey => "profile-key",
            Self::Xauth => "xauth",
        }
    }

    /// The VPN client domain's write, for the controls a role may use.
    pub(crate) const fn write(self) -> &'static str {
        match self {
            Self::Password => "ppp_password",
            Self::Ipsec => "ipsec_psk",
            Self::ProfileKey => "profile_psk",
            Self::Xauth => "profile_xauth",
        }
    }

    /// The VPN client domain's write, with its audit action id.
    const fn operation(self) -> Operation {
        let action = match self {
            Self::Password => "web.vpn_password",
            Self::Ipsec => "web.vpn_ipsec_psk",
            Self::ProfileKey => "web.vpn_profile_psk",
            Self::Xauth => "web.vpn_xauth_password",
        };
        Operation::write(&vpn_clients::DESCRIPTOR, self.write(), action)
    }

    /// The row action opening the dialog.
    pub(crate) const fn action(self) -> MessageKey {
        match self {
            Self::Password => keys::WEB_SECRET_SET_PASSWORD,
            Self::Ipsec => keys::WEB_SECRET_SET_IPSEC,
            Self::ProfileKey => keys::WEB_SECRET_SET_PSK,
            Self::Xauth => keys::WEB_SECRET_SET_XAUTH,
        }
    }

    /// The domain's credential of the connection or profile `name`.
    const fn target(self, name: ObjectName) -> CredentialTarget {
        match self {
            Self::Password => CredentialTarget::Ppp(name),
            Self::Ipsec => CredentialTarget::IpsecInterface(name),
            Self::ProfileKey => CredentialTarget::ProfilePreshared(name),
            Self::Xauth => CredentialTarget::ProfileXauth(name),
        }
    }

    /// What the credential is called, for the outcome.
    const fn label(self) -> MessageKey {
        match self {
            Self::Password | Self::Xauth => keys::WEB_INTERNET_PASSWORD,
            Self::Ipsec | Self::ProfileKey => keys::WEB_VPN_PRESHARED,
        }
    }

    /// The dialog title, with `$name`.
    const fn title(self) -> MessageKey {
        match self {
            Self::Password => keys::WEB_SECRET_VPN_PASSWORD_TITLE,
            Self::Ipsec => keys::WEB_SECRET_VPN_IPSEC_TITLE,
            Self::ProfileKey => keys::WEB_SECRET_VPN_PROFILE_TITLE,
            Self::Xauth => keys::WEB_SECRET_VPN_XAUTH_TITLE,
        }
    }

    /// The credentials a client offers: per connection, or per IPsec profile with its name.
    pub(crate) fn offered(client: &VpnClientStatus) -> Vec<(Self, String)> {
        let connection = |kinds: &[Self]| {
            kinds
                .iter()
                .map(|kind| (*kind, client.id.clone()))
                .collect()
        };
        match client.client_type {
            VpnClientType::L2tpIpsec => connection(&[Self::Password, Self::Ipsec]),
            VpnClientType::Pptp | VpnClientType::Sstp => connection(&[Self::Password]),
            VpnClientType::Ipsec => client
                .ipsec
                .as_ref()
                .and_then(|ipsec| ipsec.profile.clone())
                .map(|profile| vec![(Self::ProfileKey, profile.clone()), (Self::Xauth, profile)])
                .unwrap_or_default(),
            VpnClientType::WireGuard
            | VpnClientType::OpenVpn
            | VpnClientType::ZeroTier
            | VpnClientType::OpenConnect
            | VpnClientType::Proxy
            | _ => Vec::new(),
        }
    }

    /// Whether `clients` offer this credential for `name`.
    fn known(self, clients: &[VpnClientStatus], name: &str) -> bool {
        clients
            .iter()
            .flat_map(Self::offered)
            .any(|(kind, offered)| kind == self && offered == name)
    }

    /// The dialog for `name` on `router`.
    fn dialog(self, router: &str, name: &ObjectName, locale: Locale) -> SecretDialog {
        let post_to = with_query(
            &format!("/ui/r/{router}/vpn/credential"),
            &[("kind", self.slug()), ("name", name.as_str())],
        );
        let label = match self {
            Self::Password | Self::Xauth => keys::WEB_SECRET_NEW_PASSWORD,
            Self::Ipsec | Self::ProfileKey => keys::WEB_SECRET_NEW_KEY,
        };
        SecretDialog::new(
            locale,
            (self.title(), name.as_str()),
            post_to,
            (label, keys::WEB_SECRET_KEEP_HELP),
        )
    }
}

/// The kind and the object name of a request.
///
/// # Errors
///
/// Answers 404 for a missing or unknown kind or name.
fn requested(query: Vec<(String, String)>) -> Result<(Kind, ObjectName), Answer> {
    let params = Params::new(query, Vec::new());
    let kind = params
        .get("kind")
        .and_then(Kind::from_slug)
        .ok_or_else(missing)?;
    Ok((kind, params.object("name")?))
}

/// `GET /ui/r/{router}/vpn/credential?kind=&name=`: the dialog; it never holds the stored
/// value.
///
/// # Errors
///
/// Answers 404 for a missing kind or name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn credential_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let (kind, name) = requested(query)?;
    let action = kind.operation().open(&state, &user, &router).await?;
    Ok(kind.dialog(&router, &name, action.locale()).show())
}

/// `POST /ui/r/{router}/vpn/credential?kind=&name=`: sets the value typed twice in the
/// form body, for a connection or a profile the router lists.
///
/// # Errors
///
/// Answers 404 for an unknown connection or profile, the dialog with its error (422), and
/// what the kit answers when the router or the permission is missing.
pub(crate) async fn credential(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let (kind, name) = requested(query)?;
    let action = kind.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    let shown = kind.dialog(&router, &name, locale);
    let secret = match entry(&mut form) {
        Entry::Keep => return Ok(unchanged(action).await),
        Entry::Mismatch => {
            action.abandon("validation_failed").await;
            return Err(shown.mismatch());
        }
        Entry::New(typed) => typed,
    };
    let domain = action.context().await?;
    match vpn_clients::read_clients(&domain).await {
        Ok(clients) if kind.known(&clients, name.as_str()) => {}
        Ok(_) => {
            action.abandon("not_found").await;
            return Err(missing());
        }
        Err(_) => {
            action.abandon("unreachable").await;
            return Err(unusable(locale, Family::Changes.unreachable()));
        }
    }
    let target = kind.target(name);
    if let Err(error) = secrets::plan(&domain, &target, secret.clone()) {
        let failure = plan_failure(Family::Changes, locale, &error);
        action.abandon(failure.audit()).await;
        return Err(shown.secret_error(failure.message().to_owned()));
    }
    let applied = action
        .run_with(Risk::Write, async move |changes, context| {
            secrets::apply(changes, context, &target, secret)
                .await
                .map(|()| Applied::Done { unsaved: true })
        })
        .await;
    let outcome = verified(applied, locale, kind.label());
    Ok(changed(outcome, None, None, locale))
}
