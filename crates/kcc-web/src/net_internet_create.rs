//! Add connection on the internet page.
//!
//! It creates an IPoE, PPPoE, L2TP or PPTP interface with the lines it needs, as one
//! change: DHCP addressing for IPoE, and for PPP the connection it runs over and the user
//! name when given.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{
    DomainError, RouterCtx,
    interfaces::{self, ManagementVerdict},
    wan,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{merged, refreshed},
    net_pages::{Call, Tab},
    net_wan::{Kind, Link, links},
    page_kit::{
        action::Operation,
        change::Change,
        form::{Choice, FormDialog, Input},
        request::Params,
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// Adding a connection, audited as `web.wan_create`.
const CREATE: Operation = Operation::write(&wan::DESCRIPTOR, "create", "web.wan_create");

/// Longest name and user name accepted, in characters.
const NAME_CHARS: usize = 64;

/// The values typed into the Add connection dialog.
#[derive(Debug, Default)]
struct Draft {
    /// Connection type.
    kind: String,
    /// Interface name.
    name: String,
    /// Connection a tunnel runs over; empty for none.
    via: String,
    /// PPP user name; empty for none.
    identity: String,
}

/// A connection the Add connection dialog accepted.
struct Checked {
    /// Connection type.
    kind: Kind,
    /// Interface name.
    name: ObjectName,
    /// Connection a tunnel runs over.
    via: Option<ObjectName>,
    /// PPP user name.
    identity: Option<String>,
}

impl Draft {
    /// The values of `params`.
    fn from_params(params: &Params) -> Self {
        Self {
            kind: params.text("kind").to_owned(),
            name: params.text("name").trim().to_owned(),
            via: params.text("via").to_owned(),
            identity: params.text("identity").trim().to_owned(),
        }
    }

    /// The dialog showing these values on `router` in `locale`; `vias` are the connections
    /// a tunnel may run over.
    fn form(&self, router: &str, locale: Locale, vias: &[String]) -> FormDialog {
        let kinds = Kind::ALL
            .into_iter()
            .map(|kind| Choice::word(locale, kind.slug(), kind.label()))
            .collect();
        let mut via_choices = vec![Choice::word(locale, "", keys::WEB_INTERNET_NOT_SET)];
        via_choices.extend(vias.iter().map(|via| Choice::plain(via)));
        FormDialog::network(
            locale,
            tr(locale, keys::WEB_INTERNET_CREATE_TITLE, None),
            format!("/ui/r/{router}/internet/create"),
        )
        .with_input(Input::new("kind", keys::WEB_INTERNET_KIND, self.kind.clone()).select(kinds))
        .with_input(
            Input::new("name", keys::WEB_INTERNET_NAME, self.name.clone())
                .max_chars(NAME_CHARS)
                .rule(keys::WEB_INTERNET_NAME_ERROR)
                .help(keys::WEB_INTERNET_NAME_HELP),
        )
        .with_input(
            Input::new("via", keys::WEB_INTERNET_VIA, self.via.clone())
                .select(via_choices)
                .help(keys::WEB_INTERNET_VIA_HELP),
        )
        .with_input(
            Input::new(
                "identity",
                keys::WEB_INTERNET_IDENTITY,
                self.identity.clone(),
            )
            .max_chars(NAME_CHARS)
            .optional()
            .rule(keys::WEB_INTERNET_IDENTITY_ERROR)
            .help(keys::WEB_INTERNET_IDENTITY_HELP),
        )
        .submit(keys::WEB_INTERNET_ADD)
    }

    /// The connection, when every value is valid. `taken` are the router's interface
    /// names, `vias` the connections a tunnel may run over.
    ///
    /// # Errors
    ///
    /// Returns each invalid field with the message saying what a valid value is.
    fn check(
        &self,
        taken: &[String],
        vias: &[String],
    ) -> Result<Checked, Vec<(&'static str, MessageKey)>> {
        let mut problems = Vec::new();
        let kind = Kind::from_slug(&self.kind);
        if kind.is_none() {
            problems.push(("kind", keys::WEB_INTERNET_KIND_ERROR));
        }
        let name = ObjectName::try_from(self.name.clone())
            .ok()
            .filter(|name| kind.is_none_or(|found| named_as(found, name.as_str())));
        match &name {
            None => problems.push(("name", keys::WEB_INTERNET_NAME_ERROR)),
            Some(found) if taken.iter().any(|other| other == found.as_str()) => {
                problems.push(("name", keys::WEB_INTERNET_NAME_EXISTS));
            }
            Some(_) => {}
        }
        let ppp = kind.is_some_and(Kind::ppp);
        let via = (ppp && !self.via.is_empty()).then(|| {
            vias.contains(&self.via)
                .then(|| ObjectName::try_from(self.via.clone()).ok())
                .flatten()
        });
        if via == Some(None) {
            problems.push(("via", keys::WEB_INTERNET_VIA_ERROR));
        }
        let identity = (ppp && !self.identity.is_empty()).then(|| {
            ((1..=NAME_CHARS).contains(&self.identity.chars().count())
                && !self.identity.chars().any(char::is_control))
            .then(|| self.identity.clone())
        });
        if identity == Some(None) {
            problems.push(("identity", keys::WEB_INTERNET_IDENTITY_ERROR));
        }
        match (kind, name) {
            (Some(found_kind), Some(found_name)) if problems.is_empty() => Ok(Checked {
                kind: found_kind,
                name: found_name,
                via: via.flatten(),
                identity: identity.flatten(),
            }),
            (Some(_) | None, Some(_) | None) => Err(problems),
        }
    }
}

/// Whether `name` names a connection of `kind`: a tunnel's name is its type's prefix and
/// one to three digits; an IPoE name starts with no tunnel prefix.
fn named_as(kind: Kind, name: &str) -> bool {
    kind.prefix().map_or_else(
        || {
            !Kind::ALL
                .into_iter()
                .filter_map(Kind::prefix)
                .any(|prefix| name.starts_with(prefix))
        },
        |prefix| {
            name.strip_prefix(prefix).is_some_and(|number| {
                (1..=3).contains(&number.len()) && number.bytes().all(|byte| byte.is_ascii_digit())
            })
        },
    )
}

/// The IPoE connections among `found`, which a tunnel may run over.
fn ipoe(found: &[Link]) -> Vec<String> {
    found
        .iter()
        .filter(|link| link.kind() == Some(Kind::Ipoe))
        .map(|link| link.id().to_owned())
        .collect()
}

/// The lines that create `checked` on the router of `domain`, as one request.
///
/// # Errors
///
/// Returns the catalog's findings.
async fn plan_create(checked: &Checked, domain: &RouterCtx) -> Result<Planned, DomainError> {
    let name = &checked.name;
    let mut operations = vec![wan::plan_create(domain, name).await?];
    if checked.kind == Kind::Ipoe {
        operations.push(wan::plan_dhcp(
            domain,
            name,
            ManagementVerdict::NotManagement,
        )?);
    }
    if let Some(via) = &checked.via {
        operations.push(wan::plan_connect_via(domain, name, via)?);
    }
    if let Some(identity) = &checked.identity {
        operations.push(wan::plan_identity(domain, name, identity)?);
    }
    let requests = operations
        .iter()
        .map(|operation| wan::change_request(name, operation))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Planned::of(&operations, Change::Cli(merged(requests)?)))
}

/// `GET /ui/r/{router}/internet/create`: the Add connection dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn create_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let vias = ipoe(&links(&domain).await.unwrap_or_default());
    let draft = Draft {
        kind: Kind::Pppoe.slug().to_owned(),
        ..Draft::default()
    };
    Ok(draft.form(&router, action.locale(), &vias).show())
}

/// `POST /ui/r/{router}/internet/create`: checks the new connection, plans its lines with
/// the WAN domain and runs them as one change.
///
/// # Errors
///
/// Answers the dialog with its field errors (422) when a value is invalid, and what the
/// kit answers when the router or the permission is missing.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(Vec::new(), form);
    let draft = Draft::from_params(&params);
    let action = CREATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let vias = ipoe(&links(&domain).await.unwrap_or_default());
    let taken: Vec<String> = interfaces::read_interfaces(&domain)
        .await
        .map_or_default(|found| found.into_keys().collect());
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    Ok(
        Submission::new(action, &params, draft.form(&router, locale, &vias))
            .submit(
                |_params| draft.check(&taken, &vias).map_err(Invalid::from),
                async |checked, planning| plan_create(&checked, planning).await,
                async |planning| refreshed(call, planning).await,
            )
            .await,
    )
}
