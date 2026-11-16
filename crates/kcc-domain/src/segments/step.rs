//! Shared segment step definitions, validation, execution, and verification.

mod definitions;

use core::{result::Result as CoreResult, str::from_utf8};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, WorkflowError},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

use super::SegmentSpec;
use crate::{ChangeOp, DomainError, Result, RouterCtx, verification};

/// Direction in which a segment definition is executed.
#[derive(Clone, Copy)]
pub(super) enum Direction {
    /// Apply create commands and require their probes.
    Create,
    /// Apply delete commands and require their probes to disappear.
    Delete,
}

/// One reversible and independently verifiable segment step.
#[derive(Debug)]
pub(super) struct Step {
    /// Stable step label returned in errors.
    name: String,
    /// Positive CLI command and the request it renders.
    create: StepLine,
    /// Negative CLI command and the request it renders.
    delete: StepLine,
    /// Canonical top-level command proving this step exists.
    context: String,
    /// Optional canonical child command under `context`.
    child: Option<String>,
    /// Interface context that may need cleanup when this operation introduced it.
    cleanup_context: Option<String>,
    /// Whether `cleanup_context` was absent from the baseline.
    cleanup_owned: bool,
}

impl Step {
    /// Returns the stable step label.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Marks cleanup contexts recovered from the persisted ownership record.
    pub(super) fn restore_cleanup(&mut self, owned: &[String]) {
        self.cleanup_owned = self
            .cleanup_context
            .as_ref()
            .is_some_and(|context| owned.contains(context));
    }

    /// Checks whether one context child belongs to this exact step definition.
    pub(super) fn owns_child(&self, context: &str, child: &str) -> bool {
        self.context == context && self.child.as_deref() == Some(child)
    }

    /// Returns the generated command in one execution direction.
    pub(super) fn line(&self, direction: Direction) -> &str {
        &self.direction(direction).line
    }

    /// Returns the command and request of one execution direction.
    const fn direction(&self, direction: Direction) -> &StepLine {
        match direction {
            Direction::Create => &self.create,
            Direction::Delete => &self.delete,
        }
    }
}

/// One CLI command of a step and the catalog request it renders.
#[derive(Debug)]
struct StepLine {
    /// Catalog validation path.
    catalog_path: &'static str,
    /// Catalog validation body.
    body: Value,
    /// CLI command.
    line: String,
}

/// Pairs a CLI command with the catalog request it renders.
const fn cli(catalog_path: &'static str, body: Value, line: String) -> StepLine {
    StepLine {
        catalog_path,
        body,
        line,
    }
}

/// Verification half of one step definition.
struct StepVerification {
    /// Canonical top-level command.
    context: String,
    /// Optional canonical child.
    child: Option<String>,
    /// Optional context cleaned only when introduced by this operation.
    cleanup_context: Option<String>,
}

/// Builds one step from its two commands and verification values.
fn step(name: String, create: StepLine, delete: StepLine, verification: StepVerification) -> Step {
    Step {
        name,
        create,
        delete,
        context: verification.context,
        child: verification.child,
        cleanup_context: verification.cleanup_context,
        cleanup_owned: false,
    }
}

/// Builds the single ordered definition shared by create, delete, and rollback.
pub(super) fn steps(segment: &SegmentSpec) -> Vec<Step> {
    let vlan = format!("Vlan{}", segment.id);
    let bridge = format!("Bridge{}", segment.id);
    let pool = format!("Pool{}", segment.id);
    let mut definitions = vec![step(
        "vlan-subinterface".to_owned(),
        cli(
            "interface vlan-id",
            json!({"vid":segment.vlan_id}),
            format!("interface {vlan} vlan-id {}", segment.vlan_id),
        ),
        cli(
            "interface",
            json!({"name":vlan,"no":true}),
            format!("no interface {vlan}"),
        ),
        StepVerification {
            context: format!("interface {vlan}"),
            child: Some(format!("vlan-id {}", segment.vlan_id)),
            cleanup_context: None,
        },
    )];
    for port in &segment.switch_ports {
        definitions.push(step(
            format!("trunk-{port}"),
            cli(
                "interface switchport trunk",
                json!({"vid":segment.vlan_id}),
                format!("interface {port} switchport trunk vlan {}", segment.vlan_id),
            ),
            cli(
                "interface switchport trunk",
                json!({"vid":segment.vlan_id,"no":true}),
                format!(
                    "no interface {port} switchport trunk vlan {}",
                    segment.vlan_id
                ),
            ),
            StepVerification {
                context: format!("interface {port}"),
                child: Some(format!("switchport trunk vlan {}", segment.vlan_id)),
                cleanup_context: Some(format!("interface {port}")),
            },
        ));
    }
    definitions.extend(definitions::core_steps(segment, &vlan, &bridge, &pool));
    definitions::append_optional_steps(&mut definitions, segment, &bridge);
    definitions
}

/// Records which cleanup candidates were absent before segment creation.
pub(super) async fn record_baseline(
    router: &RouterCtx,
    definitions: &mut [Step],
) -> CoreResult<(), WorkflowError> {
    let text = running_config(router).await?;
    for definition in definitions {
        definition.cleanup_owned = definition
            .cleanup_context
            .as_deref()
            .is_some_and(|context| !context_has_child(&text, context, None));
    }
    Ok(())
}

/// Plans the selected direction as one aggregate `ChangeOp`.
pub(super) fn plan(
    router: &RouterCtx,
    definitions: &[Step],
    direction: Direction,
    risk: Risk,
) -> Result<ChangeOp> {
    let iterator: Box<dyn Iterator<Item = &Step> + '_> = match direction {
        Direction::Create => Box::new(definitions.iter()),
        Direction::Delete => Box::new(definitions.iter().rev()),
    };
    let requests = iterator
        .map(|definition| validate(router, definition.direction(direction)))
        .collect::<Result<Vec<_>>>()?;
    Ok(ChangeOp::new(
        requests,
        Vec::new(),
        risk,
        Permission::Write,
        false,
    ))
}

/// Executes and verifies one step in the selected direction.
pub(super) async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    definition: &Step,
    direction: Direction,
) -> CoreResult<(), WorkflowError> {
    let command = definition.direction(direction);
    let validated = validate(router, command).map_err(|_error| WorkflowError::InvalidResponse)?;
    let mut commands = vec![ValidatedCli::new(command.line.clone(), validated)?];
    if matches!(direction, Direction::Delete)
        && definition.cleanup_owned
        && let Some(context) = &definition.cleanup_context
    {
        let name = context
            .strip_prefix("interface ")
            .ok_or(WorkflowError::InvalidResponse)?;
        let cleanup = router
            .catalog
            .validate(
                "interface",
                HttpMethod::Post,
                &json!({"name":name,"no":true}),
            )
            .map_err(|_issues| WorkflowError::InvalidResponse)?;
        commands.push(ValidatedCli::new(format!("no {context}"), cleanup)?);
    }
    let request = CliChangeRequest::new(
        commands,
        Vec::new(),
        Permission::Write,
        json!({"operation":"segment","step":definition.name}),
    );
    let verified_request =
        verification::complete(request).map_err(|_error| WorkflowError::InvalidResponse)?;
    drop(changes.apply_cli(verified_request).await?);
    let text = running_config(router).await?;
    let present = context_has_child(&text, &definition.context, definition.child.as_deref());
    let verified = match direction {
        Direction::Create => present,
        Direction::Delete => !present,
    };
    if !verified {
        return Err(WorkflowError::VerificationFailed {
            field: format!("segment/{}", definition.name),
        });
    }
    Ok(())
}

/// Downloads canonical running configuration text.
pub(super) async fn running_config(router: &RouterCtx) -> CoreResult<String, WorkflowError> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    from_utf8(bytes.expose_secret())
        .map(str::to_owned)
        .map_err(|_error| WorkflowError::InvalidResponse)
}

/// Finds an exact top-level command and optional exact child in canonical config text.
pub(super) fn context_has_child(text: &str, context: &str, child: Option<&str>) -> bool {
    let mut selected = false;
    for line in text.lines() {
        if line.starts_with(' ') {
            if selected && line.trim() == child.unwrap_or_default() {
                return true;
            }
        } else {
            selected = line == context;
            if selected && child.is_none() {
                return true;
            }
        }
    }
    false
}

/// Catalog-validates one step command while retaining its dynamic context in the CLI line.
fn validate(router: &RouterCtx, command: &StepLine) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(command.catalog_path, HttpMethod::Post, &command.body)
        .map_err(|issues| DomainError::Validation { issues })
}
