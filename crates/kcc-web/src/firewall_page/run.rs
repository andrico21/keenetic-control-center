//! How a firewall change runs: the risk it carries, the confirmation it needs, the change
//! and its read-back from a fresh running configuration.
//!
//! A change to a list applied to an interface, or applying a list to one, cuts kcc off
//! when that interface carries kcc's connection to the router. Such a change is a
//! management change: it asks first, needs the `Destructive` permission and runs inside
//! the router's fail-safe timer. Every other firewall change is a plain write.

use axum::{http::HeaderMap, response::Response};
use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, WorkflowError},
};
use kcc_catalog::Risk;
use kcc_domain::{RouterCtx, firewall::management::interfaces_risk};
use url::form_urlencoded;

use super::{
    snapshot::{self, Binding, Snapshot},
    views::{Spot, refreshed},
};
use crate::{
    authz::CurrentUser,
    page_kit::{
        action::Action,
        change::Applied,
        confirm::{Confirmation, Resubmit},
        gate::allowed,
        respond::Answer,
    },
    routing_page::reply::answer,
    system_pages::shared::forbidden,
};

/// What the router's firewall must show after a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    /// The list holds the rule `words` exactly `count` times.
    Count {
        /// The list.
        list: String,
        /// The rule's words.
        words: Vec<String>,
        /// How many times.
        count: usize,
    },
    /// The rule `words` stands at `position` of the list.
    At {
        /// The list.
        list: String,
        /// The position, from 0.
        position: usize,
        /// The rule's words.
        words: Vec<String>,
    },
    /// Rule `index` of the list is disabled, or not.
    Disabled {
        /// The list.
        list: String,
        /// The rule's position.
        index: usize,
        /// Whether it is disabled.
        disabled: bool,
    },
    /// Rule `index` of the list has `value` as its description or schedule.
    Property {
        /// The list.
        list: String,
        /// The rule's position.
        index: usize,
        /// `description` or `schedule`.
        keyword: &'static str,
        /// The value; `None` for none.
        value: Option<String>,
    },
    /// The binding is there, or not.
    Bound {
        /// The binding.
        binding: Binding,
        /// Whether it is there.
        present: bool,
    },
}

impl Expect {
    /// Whether `snapshot` shows what the change promised.
    fn holds(&self, snapshot: &Snapshot) -> bool {
        match self {
            Self::Count { list, words, count } => {
                let found = snapshot.list(list).map_or(0, |shown| {
                    shown
                        .entries()
                        .iter()
                        .filter(|entry| entry.rule().words() == words.as_slice())
                        .count()
                });
                found == *count
            }
            Self::At {
                list,
                position,
                words,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*position))
                .is_some_and(|entry| entry.rule().words() == words.as_slice()),
            Self::Disabled {
                list,
                index,
                disabled,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*index))
                .is_some_and(|entry| entry.disabled() == *disabled),
            Self::Property {
                list,
                index,
                keyword,
                value,
            } => snapshot
                .list(list)
                .and_then(|shown| shown.entry(*index))
                .is_some_and(|entry| {
                    let shown = if *keyword == "description" {
                        entry.description()
                    } else {
                        entry.schedule()
                    };
                    shown == value.as_deref()
                }),
            Self::Bound { binding, present } => snapshot.bindings().contains(binding) == *present,
        }
    }

    /// What a failed read-back names.
    fn field(&self) -> String {
        match self {
            Self::Count {
                list,
                words: _,
                count: _,
            }
            | Self::At {
                list,
                position: _,
                words: _,
            }
            | Self::Disabled {
                list,
                index: _,
                disabled: _,
            }
            | Self::Property {
                list,
                index: _,
                keyword: _,
                value: _,
            } => format!("access-list {list}"),
            Self::Bound {
                binding,
                present: _,
            } => format!("interface {} ip access-group", binding.interface()),
        }
    }
}

/// A firewall change ready to run: its request, what it must show afterwards and the
/// interfaces whose traffic it changes.
pub(crate) struct Planned {
    /// The CLI request.
    request: CliChangeRequest,
    /// The read-back.
    expect: Expect,
    /// Interfaces whose traffic the change filters differently.
    interfaces: Vec<String>,
}

impl Planned {
    /// `request`, read back as `expect`, changing the traffic of `interfaces`.
    pub(crate) const fn new(
        request: CliChangeRequest,
        expect: Expect,
        interfaces: Vec<String>,
    ) -> Self {
        Self {
            request,
            expect,
            interfaces,
        }
    }
}

/// Who sent the change and from where: the page's headers and the request's pairs, for
/// the region read back and the confirmation sent again.
#[derive(Clone, Copy)]
pub(crate) struct Sender<'request> {
    /// The signed-in user.
    user: &'request CurrentUser,
    /// The page's headers.
    headers: &'request HeaderMap,
    /// The action's path.
    path: &'request str,
    /// The query and form pairs.
    pairs: &'request [(String, String)],
}

impl<'request> Sender<'request> {
    /// The change `user` sent from the page of `headers` to `path` with `pairs`.
    pub(crate) const fn new(
        user: &'request CurrentUser,
        headers: &'request HeaderMap,
        (path, pairs): (&'request str, &'request [(String, String)]),
    ) -> Self {
        Self {
            user,
            headers,
            path,
            pairs,
        }
    }

    /// The address the confirmation sends the change to again, with its values.
    fn resubmit(&self) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in self.pairs {
            if name != "confirm" && name != "confirm_name" {
                let _: &mut form_urlencoded::Serializer<'_, String> =
                    query.append_pair(name, value);
            }
        }
        format!("{}?{}", self.path, query.finish())
    }
}

/// Asks first when `planned` is a management change, runs it, reads the firewall back and
/// answers with the outcome and the `spot` region read back.
///
/// # Errors
///
/// Answers 403, audited, when a management change needs a permission the role lacks.
// NOT cancel-safe: see `Action::run_with`.
pub(crate) async fn submit(
    action: Action<'_>,
    domain: &RouterCtx,
    planned: Planned,
    (sender, spot): (Sender<'_>, Spot),
) -> Result<Response, Answer> {
    let locale = action.locale();
    let router = action.router();
    let risk = interfaces_risk(domain, &planned.interfaces).await;
    let needed = [Permission::Write, Permission::Destructive];
    if risk >= Risk::Management && !allowed(sender.user, router, &needed) {
        action.abandon("forbidden").await;
        return Err(forbidden(locale));
    }
    let confirmation = Confirmation::from_pairs(sender.pairs);
    let resubmit = Resubmit::new(sender.resubmit(), "#page-outcome");
    if let Some(prompt) = action.confirm(risk, &confirmation, resubmit) {
        return Ok(prompt);
    }
    let Planned {
        request,
        expect,
        interfaces: _,
    } = planned;
    let outcome = action
        .run_with(risk, async |changes, context| {
            let result = changes.apply_cli(request).await?;
            let fresh = snapshot::read(context)
                .await
                .map_err(|_message| WorkflowError::InvalidResponse)?;
            if !expect.holds(&fresh) {
                return Err(WorkflowError::VerificationFailed {
                    field: expect.field(),
                });
            }
            Ok(Applied::Cli {
                unsaved: result.unsaved,
                responses: result.responses,
            })
        })
        .await;
    let shown = if outcome.succeeded() {
        refreshed(
            domain,
            (router, sender.user),
            (spot, sender.headers),
            locale,
        )
        .await
    } else {
        None
    };
    Ok(answer(outcome, shown, locale))
}
