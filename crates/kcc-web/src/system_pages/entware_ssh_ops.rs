//! The package actions of the SSH section, and how a change starts as a job.
//!
//! The lists are reads, bounded by the page's read limit. Changes (update, install,
//! remove, upgrade, and the service actions) run as write jobs of the router, followed
//! through the job feed; each job reads its result back. Names are parsed by the closed
//! grammars of `kcc-ssh` before anything is sent.

use alloc::sync::Arc;

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_domain::{
    RouterCtx,
    entware::ssh::ops::{
        self,
        job::{self, Mutation, Request},
    },
};
use kcc_i18n::{bundle::tr, keys};
use kcc_ssh::grammar::PackageName;

use super::{
    entware_ssh_desk::{Desk, Doing},
    entware_ssh_views::PackagesView,
    jobs::JobPanel,
    shared::{merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        confirm::Resubmit,
        outcome::Failure,
        request::{missing, with_query},
        respond::{Answer, close_dialog},
    },
};

/// A package action.
#[derive(Clone, Copy)]
enum PackageOp {
    /// The installed packages.
    List,
    /// The packages with an upgrade.
    Upgradable,
    /// `opkg update`.
    Update,
    /// Installs the named package.
    Install,
    /// Removes the named package.
    Remove,
    /// Upgrades the named package.
    Upgrade,
}

impl PackageOp {
    /// The action named `word`, and its audit id.
    fn parse(word: &str) -> Option<(Self, &'static str)> {
        Some(match word {
            "list" => (Self::List, "web.entware_ssh_packages_list"),
            "upgradable" => (Self::Upgradable, "web.entware_ssh_packages_upgradable"),
            "update" => (Self::Update, "web.entware_ssh_update"),
            "install" => (Self::Install, "web.entware_ssh_install"),
            "remove" => (Self::Remove, "web.entware_ssh_remove"),
            "upgrade" => (Self::Upgrade, "web.entware_ssh_upgrade"),
            _ => return None,
        })
    }
}

/// Where the dialog sends `word` of `family` again on `router`, with `name`, showing the
/// answer in `target`.
pub(super) fn again(
    router: &str,
    (family, word): (&str, &str),
    name: &str,
    target: &'static str,
) -> Resubmit {
    let path = format!("/ui/r/{router}/system/entware/ssh/{family}/{word}");
    let action = if name.is_empty() {
        path
    } else {
        with_query(&path, &[("name", name)])
    };
    Resubmit::new(action, target)
}

/// `POST .../entware/ssh/packages/{op}`: `list`, `upgradable`, `update`, and `install`,
/// `remove` or `upgrade` with `name`.
///
/// # Errors
///
/// What the desk answers, and 404 for another action.
// NOT cancel-safe: a change job may be started, and its audit entry queued, before the future
// is dropped.
pub(crate) async fn packages(
    State(state): State<WebState>,
    Path((router, op)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let (action, audited) = PackageOp::parse(&op).ok_or_else(missing)?;
    let desk = Desk::open(&state, &user, &router, audited).await?;
    let pairs = merged(query.as_deref(), form);
    let typed = value(&pairs, "name").unwrap_or_default();
    let named = match action {
        PackageOp::List | PackageOp::Upgradable | PackageOp::Update => None,
        PackageOp::Install | PackageOp::Remove | PackageOp::Upgrade => {
            let Ok(name) = PackageName::parse(typed) else {
                let rule = tr(desk.locale(), keys::WEB_SYSTEM_ENTWARE_SSH_NAME_RULE, None);
                return Ok(desk.refuse(Failure::new(rule, "validation_failed")).await);
            };
            Some(name)
        }
    };
    let (target, doing) = match action {
        PackageOp::List | PackageOp::Upgradable => ("#entware-ssh-packages", Doing::Read),
        PackageOp::Update | PackageOp::Install | PackageOp::Remove | PackageOp::Upgrade => {
            ("#page-outcome", Doing::Change)
        }
    };
    if let Some(prompt) = desk.ask(
        &pairs,
        again(&router, ("packages", &op), typed, target),
        doing,
    ) {
        return Ok(prompt);
    }
    let domain = desk.context().await?;
    let (services, caller) = (desk.services(), desk.caller());
    let mutation = match (action, named) {
        (PackageOp::List, _) => {
            let found = desk
                .read(ops::packages_list(services, &domain, &caller))
                .await?;
            return Ok(close_dialog(
                PackagesView::new(desk.locale(), &found, false).answer(),
            ));
        }
        (PackageOp::Upgradable, _) => {
            let found = desk
                .read(ops::packages_upgradable(services, &domain, &caller))
                .await?;
            return Ok(close_dialog(
                PackagesView::new(desk.locale(), &found, true).answer(),
            ));
        }
        (PackageOp::Update, _) => Mutation::Update,
        (PackageOp::Install, Some(name)) => Mutation::Install(name),
        (PackageOp::Remove, Some(name)) => Mutation::Remove(name),
        (PackageOp::Upgrade, Some(name)) => Mutation::Upgrade(name),
        (PackageOp::Install | PackageOp::Remove | PackageOp::Upgrade, None) => {
            return Err(missing());
        }
    };
    Ok(Box::pin(started(&desk, domain, mutation)).await)
}

/// Starts `mutation` as a write job of the router and answers with its panel; the page
/// audits a job that did not start, which the job runner does not.
// NOT cancel-safe: the job may be started, and its audit entry queued, before the future is
// dropped.
pub(super) async fn started(desk: &Desk<'_>, domain: RouterCtx, mutation: Mutation) -> Response {
    let state = desk.state();
    let Some(jobs) = state.advanced().jobs().cloned() else {
        let message = tr(desk.locale(), keys::WEB_EXPLORER_JOBS_UNAVAILABLE, None);
        return desk.refuse(Failure::new(message, "failed")).await;
    };
    let events = jobs.subscribe();
    let user = desk.user();
    let request = Request::new(
        domain,
        desk.router().to_owned(),
        desk.actor().clone(),
        user.role().clone(),
    );
    match job::start(&jobs, Arc::clone(desk.services()), request, mutation).await {
        Ok(id) => {
            state.advanced().feeds().follow(
                Arc::clone(&jobs),
                events,
                id.clone(),
                user.username().to_owned(),
            );
            desk.record().append(state, user, "started").await;
            close_dialog(
                JobPanel::new(desk.locale(), desk.router(), id)
                    .titled(keys::WEB_SYSTEM_ENTWARE_SSH_JOB)
                    .unstoppable()
                    .answer(),
            )
        }
        Err(error) => desk.failed_unaudited(&error, None).await,
    }
}
