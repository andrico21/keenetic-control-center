//! Executes one source/target pair of the migration matrix against fake routers.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{error::Error, future::ready, pin::Pin, time::Duration};

use kcc_app::audit::{Actor, ActorKind};
use kcc_config::config_text::{flatten, parse};
use kcc_migrate::{
    apply::{Applier, ApplyRequest, ApplySource, Clock},
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, MigrationMaps, MigrationPlan, PlanError, Planner},
    source::SourceConfig,
};
use kcc_rci::{RouterUrl, SecretBytes};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, migration,
    time::{Clock as _, MockClock},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};

use super::{
    cases::{GIGA_43_FILE, Source, Target},
    source::{LiveSource, register_source, seed_source},
    support::Fixture,
};

/// Deterministic applier clock that advances the shared mock instead of sleeping.
#[derive(Debug)]
struct MatrixClock(Arc<MockClock>);

impl Clock for MatrixClock {
    fn now(&self) -> Duration {
        self.0.now()
    }
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.0.advance(duration);
        Box::pin(ready(()))
    }
}

/// Observable result of one pair.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Inventory refused the older target.
    Refused {
        /// Target requests other than reads and login.
        writes: usize,
        /// Whether running and startup configuration are byte-identical to the start.
        unchanged: bool,
    },
    /// The plan was applied, verified and committed.
    Committed {
        /// Disposition-count snapshot.
        snapshot: Value,
        /// Number of `unsupported` plan items.
        unsupported: usize,
    },
}

/// Runs one pair end to end.
///
/// # Errors
/// Returns fixture, planning or apply failures, including unresolvable input requests.
// NOT cancel-safe: starts routers and mutates the isolated target.
pub(crate) async fn run(source: Source, target: Target) -> Result<Outcome, Box<dyn Error>> {
    let clock = Arc::new(MockClock::new());
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let fake = FakeRouter::builder(target.profile()?)
        .clock(Arc::<MockClock>::clone(&clock))
        .build()?
        .with_migration(scenario);
    let fixture = Fixture::from_router(fake, DEFAULT_PASSWORD).await?;
    let live = match source.profile() {
        Some(profile) => Some(seed_source(profile, &source.seed_lines()).await?),
        None => None,
    };
    let bytes = match &live {
        Some(router) => register_source(&fixture, router).await?,
        None => SecretBytes::from(GIGA_43_FILE.as_bytes().to_vec()),
    };
    let parsed = SourceConfig::from_bytes(bytes.expose_secret())?;
    let before = (
        fixture.handle.running_config_text(),
        fixture.handle.startup_config_text(),
    );
    let client = fixture
        .registry
        .bootstrap_client(&fixture.role, "target")
        .await?;
    let collected =
        TargetInventory::collect(&InventoryClient::from_client(&client), parsed.firmware).await;
    let inventory = match collected {
        Err(InventoryError::TargetFirmwareOlder {
            source_version: _,
            target_version: _,
        }) => {
            let outcome = Outcome::Refused {
                writes: writes(&fixture.handle),
                unchanged: before
                    == (
                        fixture.handle.running_config_text(),
                        fixture.handle.startup_config_text(),
                    ),
            };
            shutdown(fixture, live).await?;
            return Ok(outcome);
        }
        other => other?,
    };
    let (plan, resolved) = resolve_plan(&parsed, &inventory, &fixture.url)?;
    let unsupported = count(&plan, "unsupported");
    if source == Source::Ultra51Vpn && unsupported != 0 {
        return Err("VPN source contains unsupported lines".into());
    }
    let snapshot = snapshot(source, target, &plan, resolved)?;
    let expected = plan
        .phases
        .additive
        .iter()
        .map(|line| line.expose_command().to_owned())
        .filter(|line| !line.starts_with("user "))
        .collect::<Vec<_>>();
    let apply_source = match &live {
        Some(_) => ApplySource::LiveRouter {
            id: "source".to_owned(),
            client: fixture.registry.client("source").await?,
        },
        None => ApplySource::File(bytes),
    };
    let mut request = ApplyRequest::new(
        Arc::clone(&fixture.workflow),
        fixture.audit.clone(),
        Actor::new(ActorKind::Cli, "operator".to_owned()),
        fixture.role.clone(),
        "target".to_owned(),
        plan,
        apply_source,
    );
    request.options.clock = Arc::new(MatrixClock(Arc::clone(&clock)));
    request.options.ack_documentation_tier = target.documentation_tier();
    let (_id, done) = Applier::start(&fixture.runner, request).await?;
    let mut applier = done.await??;
    if let Some(failure) = applier.report().failure {
        return Err(format!("apply failed: {failure:?}").into());
    }
    if !applier.report().verified {
        return Err("apply was not verified".into());
    }
    applier.commit().await?;
    let startup = flatten(&parse(&fixture.handle.startup_config_text())?)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if let Some(missing) = expected.iter().position(|line| !startup.contains(line)) {
        return Err(format!("committed startup lacks planned additive line {missing}").into());
    }
    drop(applier);
    shutdown(fixture, live).await?;
    Ok(Outcome::Committed {
        snapshot,
        unsupported,
    })
}

/// Plans, answering every input request from operator choices; anything else is fatal.
///
/// # Errors
/// Returns planning failures and requests the matrix cannot answer.
fn resolve_plan(
    source: &SourceConfig,
    inventory: &TargetInventory,
    target_url: &RouterUrl,
) -> Result<(MigrationPlan, Vec<String>), Box<dyn Error>> {
    let mut choices = Choices::default();
    let mut resolved = Vec::new();
    for _round in 0_u8..3 {
        let blocked = match Planner::plan(source, inventory, &MigrationMaps::default(), &choices) {
            Ok(plan) => return Ok((plan, resolved)),
            Err(PlanError::PlanBlocked { items }) => items,
            Err(error) => return Err(error.into()),
        };
        for item in blocked {
            let needed = item.needed_input.unwrap_or_default();
            if let Some(user) = needed.strip_prefix("new password for ") {
                let password = format!("{user}-{}", "rotated".repeat(2));
                drop(
                    choices
                        .new_passwords
                        .insert(user.to_owned(), SecretString::from(password)),
                );
                resolved.push(format!("password:{user}"));
            } else if needed == "confirm reconnect URL" {
                choices.reconnect_url = Some(target_url.as_str().to_owned());
                resolved.push("reconnect-url".to_owned());
            } else {
                return Err(
                    format!("unresolvable {:?} item {}", item.disposition, item.rule_id).into(),
                );
            }
        }
    }
    Err("plan stayed blocked after resolving every request".into())
}

/// Builds the committed disposition-count snapshot.
///
/// # Errors
/// Returns serialization failures.
fn snapshot(
    source: Source,
    target: Target,
    plan: &MigrationPlan,
    mut resolved: Vec<String>,
) -> Result<Value, Box<dyn Error>> {
    let mut dispositions = BTreeMap::<String, usize>::new();
    for item in &plan.items {
        let key = serde_json::to_value(item.disposition)?
            .as_str()
            .ok_or("disposition is not a string")?
            .to_owned();
        let slot = dispositions.entry(key).or_default();
        *slot = slot.saturating_add(1);
    }
    resolved.sort();
    Ok(json!({
        "source": source.name(),
        "target": target.name(),
        "dispositions": dispositions,
        "phases": {
            "additive": plan.phases.additive.len(),
            "prune": plan.phases.prune.len(),
            "management": plan.phases.management.len(),
        },
        "resolved_inputs": resolved,
    }))
}

/// Counts plan items with one serialized disposition.
fn count(plan: &MigrationPlan, disposition: &str) -> usize {
    plan.items
        .iter()
        .filter(|item| {
            serde_json::to_value(item.disposition)
                .is_ok_and(|value| value.as_str() == Some(disposition))
        })
        .count()
}

/// Counts target requests that are neither reads nor the login exchange.
fn writes(handle: &Handle) -> usize {
    handle
        .request_log()
        .iter()
        .filter(|record| record.method() != "GET" && record.path() != "/auth")
        .count()
}

/// Stops every router of the pair.
///
/// # Errors
/// Returns server shutdown failures.
// NOT cancel-safe: stops background servers.
async fn shutdown(fixture: Fixture, live: Option<LiveSource>) -> Result<(), Box<dyn Error>> {
    fixture.handle.shutdown().await?;
    if let Some(source) = live {
        source.shutdown().await?;
    }
    Ok(())
}
