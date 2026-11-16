//! Planning a migration: the source, the target inventory, and the planner's answers.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::permissions::{Permission, Role};
use kcc_i18n::keys;
use kcc_migrate::{
    apply::ApplySource,
    inventory::{InventoryClient, TargetInventory},
    planner::{Choices, MigrationMaps, MigrationPlan, PlanError, Planner},
    source::SourceConfig,
};
use kcc_rci::SecretBytes;
use secrecy::{ExposeSecret as _, SecretString};

use super::{
    args_migrate::PlanInput,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    secret::read_secret,
    source_arg::{self, SourceArg},
};

/// A planned migration onto the target router.
#[derive(Debug)]
pub(crate) struct Planned {
    /// Target profile id.
    target: String,
    /// The principal's role narrowed to the source and target routers.
    role: Role,
    /// The reviewed plan.
    plan: MigrationPlan,
    /// Where the applier reads the source again.
    source: ApplySource,
    /// The target inventory the plan was made against.
    inventory: TargetInventory,
    /// Replacement password of the target's own login, when the plan changes it.
    management_password: Option<SecretString>,
}

impl Planned {
    /// Reads the source and the target inventory, and plans with `input`'s answers.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, source, inventory or blocked-plan failures.
    // cancel-safe: reads the source and target only.
    pub(crate) async fn make(ctx: &Ctx, services: &Services, input: &PlanInput) -> Outcome<Self> {
        let target = ctx.router_id(services)?;
        let from = source_arg::parse(&input.from)?;
        let mut routers = vec![target.as_str()];
        routers.extend(from.router().filter(|router| *router != target));
        let role = ctx
            .principal()
            .authorize(&[Permission::Read, Permission::Migrate], &routers)?;
        let (bytes, source) = read_source(services, from).await?;
        let config = SourceConfig::from_bytes(bytes.expose_secret())
            .map_err(|error| Failure::text(Exit::Validation, &error))?;
        let client = services.registry().bootstrap_client(&role, &target).await?;
        let inventory =
            TargetInventory::collect(&InventoryClient::from_client(&client), config.firmware)
                .await
                .map_err(|error| Failure::text(Exit::Router, &error))?;
        let login = services.registry().get(&target)?.profile.login;
        let (choices, management_password) = choices(ctx, input, &login)?;
        let plan = Planner::plan(&config, &inventory, &MigrationMaps::default(), &choices)
            .map_err(|error| blocked(ctx, error))?;
        Ok(Self {
            target,
            role,
            plan,
            source,
            inventory,
            management_password,
        })
    }

    /// Target profile id.
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// The plan.
    pub(crate) const fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// The target inventory.
    pub(crate) const fn inventory(&self) -> &TargetInventory {
        &self.inventory
    }

    /// Splits into the parts the applier takes.
    pub(crate) fn into_parts(
        self,
    ) -> (
        String,
        Role,
        MigrationPlan,
        ApplySource,
        Option<SecretString>,
    ) {
        (
            self.target,
            self.role,
            self.plan,
            self.source,
            self.management_password,
        )
    }
}

/// Reads `from`, and where the applier reads it again.
///
/// # Errors
///
/// Returns file, registry, backup or router failures.
// cancel-safe: reads only.
async fn read_source(
    services: &Services,
    from: SourceArg<'_>,
) -> Outcome<(SecretBytes, ApplySource)> {
    let bytes = from.read(services).await?;
    let source = match from {
        SourceArg::File(_) => ApplySource::File(bytes.clone()),
        SourceArg::Router(id) => ApplySource::LiveRouter {
            id: id.to_owned(),
            client: services.registry().client(id).await?,
        },
        SourceArg::Backup { router, name } => ApplySource::Backup {
            store: Arc::clone(services.backups()),
            router: router.to_owned(),
            name: name.to_owned(),
        },
    };
    Ok((bytes, source))
}

/// The planner's answers: router user passwords from files and the reconnect URL.
///
/// # Errors
///
/// Returns usage or file failures.
fn choices(ctx: &Ctx, input: &PlanInput, login: &str) -> Outcome<(Choices, Option<SecretString>)> {
    let mut passwords = BTreeMap::new();
    let mut management = None;
    for pair in &input.user_passwords {
        let (user, file) = pair
            .split_once('=')
            .ok_or_else(|| Failure::text(Exit::Usage, "--user-password takes <user>=<file>"))?;
        let password = read_secret(
            Some(file.as_ref()),
            &ctx.out()
                .tr(keys::CLI_PROMPT_NEW_PASSWORD, &[("user", user)]),
        )?;
        if user == login {
            management = Some(password.clone());
        }
        drop(passwords.insert(user.to_owned(), password));
    }
    let mut choices = Choices::default();
    choices.new_passwords = passwords;
    choices.reconnect_url.clone_from(&input.reconnect_url);
    Ok((choices, management))
}

/// The blocked plan's needed inputs as a validation failure.
fn blocked(ctx: &Ctx, error: PlanError) -> Failure {
    match error {
        PlanError::PlanBlocked { items } => {
            let mut needed = items
                .iter()
                .filter_map(|item| item.needed_input.clone())
                .collect::<Vec<_>>();
            needed.extend(items.iter().filter_map(|item| {
                item.conflict.as_ref().map(|name| {
                    ctx.out()
                        .tr(keys::CLI_PLAN_CONFLICT, &[("item", name.as_str())])
                })
            }));
            Failure::message(
                Exit::Validation,
                keys::CLI_PLAN_BLOCKED,
                &[("value", &needed.join("; "))],
            )
        }
        PlanError::Rules(_) | _ => Failure::text(Exit::Generic, &error),
    }
}
