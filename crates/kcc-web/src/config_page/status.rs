//! The state of the router's configuration: unsaved changes and the fail-safe timer, read
//! from `show last-change`, with the controls the role may use on them.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_domain::{
    RouterCtx,
    configuration::{self, LastChangeState},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use crate::{
    WebState,
    authz::CurrentUser,
    page::{Localize, Shell},
    page_kit::{
        context::{Target, fragment_shell},
        family::Family,
        gate::Controls,
    },
};

/// What `show last-change` says, as the page shows it.
#[derive(Debug, Clone)]
pub(crate) struct Facts {
    /// Whether the running configuration has unsaved changes.
    unsaved: bool,
    /// Who changed it last: the user and the agent, as the router reports them.
    changed_by: Option<String>,
    /// Whether the fail-safe timer runs.
    armed: bool,
    /// The timer's time left, as people read it.
    left: Option<String>,
}

impl Facts {
    /// The facts of `state` in `locale`.
    pub(crate) fn new(state: &LastChangeState, locale: Locale) -> Self {
        let who = state.user.as_ref().filter(|text| !text.is_empty());
        let via = state.agent.as_ref().filter(|text| !text.is_empty());
        let changed_by = match (who, via) {
            (Some(name), Some(tool)) => Some(format!("{name} ({tool})")),
            (Some(only), None) | (None, Some(only)) => Some(only.clone()),
            (None, None) => None,
        };
        let safe = state.fail_safe.as_ref();
        Self {
            unsaved: state.unsaved.unwrap_or(false),
            changed_by,
            armed: safe.and_then(|timer| timer.active).unwrap_or(false),
            left: safe
                .and_then(|timer| timer.remaining)
                .map(|seconds| format::duration(locale, seconds)),
        }
    }

    /// Whether the running configuration has unsaved changes.
    pub(crate) const fn unsaved(&self) -> bool {
        self.unsaved
    }

    /// Who changed it last.
    pub(crate) fn changed_by(&self) -> Option<&str> {
        self.changed_by.as_deref()
    }

    /// Whether the fail-safe timer runs.
    pub(crate) const fn armed(&self) -> bool {
        self.armed
    }

    /// The timer's time left.
    pub(crate) fn left(&self) -> Option<&str> {
        self.left.as_deref()
    }
}

/// The status region (`#config-status`): unsaved changes and the fail-safe timer.
#[derive(Template)]
#[template(path = "partials/config_status.html")]
pub(crate) struct StatusRegion {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The router's answer.
    facts: Option<Facts>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
    /// The configuration operations the role may run and the router's catalog has.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

impl Localize for StatusRegion {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl StatusRegion {
    /// The region of `target` for `user`, read from the router now.
    // cancel-safe: reads only.
    pub(crate) async fn read(state: &WebState, target: Target<'_>, user: &CurrentUser) -> Self {
        let router = target.router();
        let mut region = Self {
            shell: fragment_shell(user.locale()),
            router: router.to_owned(),
            facts: None,
            problem: None,
            controls: Controls::default(),
            oob: false,
        };
        match target.context(state).await {
            Ok((facts, domain)) => {
                region.controls = Controls::new(user.role(), router)
                    .with_operations(configuration::DESCRIPTOR.write_ops, Some(facts.catalog()));
                match last_change(&domain).await {
                    Ok(found) => region.facts = Some(Facts::new(&found, user.locale())),
                    Err(message) => region.problem = Some(message),
                }
            }
            Err(error) => region.problem = Some(error.message(Family::Changes)),
        }
        region
    }

    /// The region for replacing the page's out of band.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// Whether the role may save.
    fn may_save(&self) -> bool {
        self.controls.allows("save")
    }

    /// Whether the role may keep the changes the fail-safe timer guards.
    fn may_commit(&self) -> bool {
        self.controls.allows("fail_safe_commit")
    }

    /// Whether the role may roll them back.
    fn may_roll_back(&self) -> bool {
        self.controls.allows("fail_safe_rollback")
    }

    /// The fail-safe timer's time left, as a sentence.
    fn timer_text(&self) -> String {
        let locale = self.shell.locale();
        self.facts.as_ref().and_then(Facts::left).map_or_else(
            || tr(locale, keys::WEB_CONFIG_TIMER_LEFT_UNKNOWN, None),
            |left| {
                let mut args = FluentArgs::new();
                args.set("value", left.to_owned());
                tr(locale, keys::WEB_CONFIG_TIMER_LEFT, Some(&args))
            },
        )
    }

    /// Who changed the configuration last, as a sentence.
    fn changed_text(&self) -> Option<String> {
        let who = self.facts.as_ref()?.changed_by()?;
        let mut args = FluentArgs::new();
        args.set("user", who.to_owned());
        Some(tr(
            self.shell.locale(),
            keys::WEB_CONFIG_CHANGED_BY,
            Some(&args),
        ))
    }
}

/// The router's `show last-change`.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with it.
// cancel-safe: reads only.
pub(crate) async fn last_change(domain: &RouterCtx) -> Result<LastChangeState, MessageKey> {
    configuration::read_last_change(domain)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "router last change could not be read");
            keys::WEB_CONFIG_STATUS_FAILED
        })
}
