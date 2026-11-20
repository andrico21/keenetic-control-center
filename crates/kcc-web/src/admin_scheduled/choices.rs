//! What the dialog offers for the chosen router and action.
//!
//! It is read when the dialog opens: the registered clients and the policies for a policy
//! switch, the presets the role may apply for a preset. A router that cannot be read
//! leaves its lists empty and says so; the other actions stay available.

use kcc_app::{
    permissions::{Permission, Role},
    registry,
    schedules::model::names::ClientMac,
};
use kcc_domain::{clients, policies};
use kcc_migrate::presets::store::{PresetError, PresetStore};
use kcc_rci::capabilities::{RouterInfo, SupportTier};

use crate::{WebState, authz::CurrentUser, blocking, page_kit::context};

/// The dialog's lists for one router and action.
#[derive(Debug, Clone, Default)]
pub(super) struct Choices {
    /// Registered clients: MAC and label.
    clients: Vec<(String, String)>,
    /// Connection policy names.
    policies: Vec<String>,
    /// Presets the role may apply: id and name.
    presets: Vec<(String, String)>,
    /// Whether the router runs a documentation-based firmware line, or its line is unknown.
    needs_ack: bool,
    /// Whether the router could not be read.
    unread: bool,
}

impl Choices {
    /// The lists `kind` needs on `router` for `user`.
    // NOT cancel-safe: it may sign in to the router first, and a sign-in dropped mid-way can leave
    // an orphaned router session. Apart from that, it only reads.
    pub(super) async fn read(
        state: &WebState,
        user: &CurrentUser,
        router: &str,
        kind: &str,
    ) -> Self {
        match kind {
            "policy_switch" => Self::policy_lists(state, user, router).await,
            "preset" => Self::preset_lists(state, user.role(), router).await,
            _ => Self::default(),
        }
    }

    /// The router's registered clients and its policies.
    // NOT cancel-safe: as `Choices::read`.
    async fn policy_lists(state: &WebState, user: &CurrentUser, router: &str) -> Self {
        let unread = Self {
            unread: true,
            ..Self::default()
        };
        let Ok(target) = context::target(state, user, router).await else {
            return unread;
        };
        let Ok((_facts, domain)) = target.context(state).await else {
            return unread;
        };
        let read = (
            clients::read_clients(&domain).await,
            policies::read::policies(&domain).await,
        );
        let (Ok(found), Ok(named)) = read else {
            let (clients_read, policies_read) = read;
            if let Some(error) = clients_read.err().or_else(|| policies_read.err()) {
                tracing::warn!(%error, router, "scheduled actions: clients or policies unread");
            }
            return unread;
        };
        let clients = found
            .into_iter()
            .filter(|client| client.registered == Some(true))
            .filter_map(|client| {
                let mac = ClientMac::parse(client.mac.as_deref()?).ok()?;
                let label = client
                    .name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .map_or_else(
                        || mac.as_str().to_owned(),
                        |name| format!("{name} ({})", mac.as_str()),
                    );
                Some((mac.as_str().to_owned(), label))
            })
            .collect();
        Self {
            clients,
            policies: named.into_iter().filter_map(|policy| policy.name).collect(),
            ..Self::default()
        }
    }

    /// The presets `role` may apply, and whether `router` needs the documentation-based
    /// firmware line acknowledged.
    // NOT cancel-safe: as `Choices::read`.
    async fn preset_lists(state: &WebState, role: &Role, router: &str) -> Self {
        let Some(fleet) = state.fleet() else {
            return Self::default();
        };
        let workflow = fleet.workflow();
        let presets = PresetStore::new(
            workflow.state().clone(),
            workflow.backups().key().duplicate(),
        );
        let reader = role.clone();
        let listed = blocking::run(move || presets.list(&reader), PresetError::Io)
            .await
            .inspect_err(|error| tracing::warn!(%error, "scheduled actions: presets unread"));
        let applicable = listed.map_or_default(|found| {
            found
                .into_iter()
                .filter(|preset| {
                    preset.source.router_id.as_deref().map_or_else(
                        || role.grants(Permission::Migrate),
                        |source| registry::authorize(role, Permission::Migrate, source).is_ok(),
                    )
                })
                .map(|preset| (preset.id, preset.name))
                .collect()
        });
        let info = fleet.registry().poll_info(router).await;
        let tier = info.as_ref().map(RouterInfo::support_tier);
        Self {
            presets: applicable,
            needs_ack: !matches!(tier, Ok(SupportTier::HardwareVerified)),
            ..Self::default()
        }
    }

    /// Registered clients: MAC and label.
    pub(super) fn clients(&self) -> &[(String, String)] {
        &self.clients
    }

    /// Connection policy names.
    pub(super) fn policies(&self) -> &[String] {
        &self.policies
    }

    /// Presets the role may apply: id and name.
    pub(super) fn presets(&self) -> &[(String, String)] {
        &self.presets
    }

    /// Whether the acknowledgement of a documentation-based firmware line is offered.
    pub(super) const fn needs_ack(&self) -> bool {
        self.needs_ack
    }

    /// Whether the router could not be read.
    pub(super) const fn unread(&self) -> bool {
        self.unread
    }
}
