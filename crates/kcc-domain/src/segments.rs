//! Reversible creation and deletion of UI-visible network segments.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "async multi-step workflow operations and planning functions are not inline candidates"
)]
#![expect(
    clippy::pub_use,
    reason = "segment discovery types are part of the segments public facade"
)]

pub mod discovery;
mod ownership;
mod rollback;
mod step;

use core::{net::Ipv4Addr, result::Result as CoreResult};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_catalog::Risk;
use serde::{Deserialize, Serialize};

pub use self::discovery::{DeleteSummary, SegmentView, VlanId};
use self::step::{Direction, Step, steps};
use crate::{
    ChangeOp, DomainDescriptor, DomainId, OperationDescriptor, Result, RouterCtx, interfaces,
};

/// Complete input for one UI-visible network segment.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SegmentSpec {
    /// Stable numeric suffix used by generated object names.
    pub id: u16,
    /// IEEE 802.1Q VLAN identifier.
    pub vlan_id: u16,
    /// Bridge IPv4 address.
    pub address: Ipv4Addr,
    /// Bridge IPv4 netmask.
    pub mask: Ipv4Addr,
    /// First DHCP pool address.
    pub dhcp_begin: Ipv4Addr,
    /// Last DHCP pool address.
    pub dhcp_end: Ipv4Addr,
    /// Physical switch ports that trunk the VLAN.
    pub switch_ports: Vec<String>,
    /// Optional access point included in the bridge.
    pub access_point: Option<String>,
    /// Optional connection-policy name created for the segment.
    pub connection_policy: Option<String>,
}

impl SegmentSpec {
    /// Creates a segment without optional Wi-Fi or connection-policy bindings.
    #[inline]
    #[must_use]
    pub const fn new(
        id: u16,
        vlan_id: u16,
        address: Ipv4Addr,
        mask: Ipv4Addr,
        dhcp_begin: Ipv4Addr,
        dhcp_end: Ipv4Addr,
        switch_ports: Vec<String>,
    ) -> Self {
        Self {
            id,
            vlan_id,
            address,
            mask,
            dhcp_begin,
            dhcp_end,
            switch_ports,
            access_point: None,
            connection_policy: None,
        }
    }

    /// Includes one Wi-Fi access point in the segment bridge.
    #[inline]
    #[must_use]
    pub fn with_access_point(mut self, access_point: String) -> Self {
        self.access_point = Some(access_point);
        self
    }

    /// Creates and assigns one optional connection policy.
    #[inline]
    #[must_use]
    pub fn with_connection_policy(mut self, policy: String) -> Self {
        self.connection_policy = Some(policy);
        self
    }
}

/// Segment lifecycle failure with the exact failed step.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SegmentError {
    /// Planning failed before execution.
    #[error(transparent)]
    Domain(#[from] crate::DomainError),
    /// A create or delete step failed after any required rollback was attempted.
    #[error("segment step {step} failed")]
    StepFailed {
        /// Stable step label.
        step: String,
        /// Workflow failure returned by the step.
        #[source]
        source: Box<WorkflowError>,
    },
    /// A rollback step failed and the router may retain partial state.
    #[error("segment step {step} failed and rollback step {rollback_step} also failed")]
    RollbackFailed {
        /// Stable original failing step label.
        step: String,
        /// Stable rollback step label.
        rollback_step: String,
        /// Rollback workflow failure.
        #[source]
        source: Box<WorkflowError>,
    },
}

/// Receipt retaining baseline facts required for lossless teardown.
#[derive(Debug)]
#[non_exhaustive]
pub struct CreatedSegment {
    /// Ordered reversible steps with baseline context ownership.
    steps: Vec<Step>,
}

/// Segment write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation("create", "interface"),
    operation("delete", "interface"),
];

/// Segments domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Segments,
    read_ops: &[OperationDescriptor {
        name: "read_segments",
        catalog_path: "show rc",
        risk: Risk::Read,
        permission: Permission::Read,
        persists_immediately: false,
    }],
    write_ops: WRITES,
    required_components: &[],
};

/// Plans all validated create requests in execution order.
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_create(router: &RouterCtx, segment: &SegmentSpec) -> Result<ChangeOp> {
    ownership::validate(segment)?;
    let definitions = steps(segment);
    let lines = definitions
        .iter()
        .map(|definition| definition.line(Direction::Create))
        .collect::<Vec<_>>();
    step::plan(
        router,
        &definitions,
        Direction::Create,
        interfaces::management::classify_generated(router, &lines).await?,
    )
}

/// Plans all validated delete requests in reverse execution order.
// cancel-safe: management classification performs read-only topology requests.
pub async fn plan_delete(router: &RouterCtx, segment: &SegmentSpec) -> Result<ChangeOp> {
    ownership::validate(segment)?;
    let definitions = steps(segment);
    let lines = definitions
        .iter()
        .map(|definition| definition.line(Direction::Delete))
        .collect::<Vec<_>>();
    step::plan(
        router,
        &definitions,
        Direction::Delete,
        interfaces::management::classify_generated(router, &lines).await?,
    )
}

/// Creates one segment, rolling applied steps back in reverse order on failure; the failed
/// step is rolled back first when its request may have changed the router.
// NOT cancel-safe: cancelled between steps, the steps already applied stay on the router
// and the reverse-order rollback never runs.
pub async fn create(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    segment: &SegmentSpec,
) -> CoreResult<CreatedSegment, SegmentError> {
    let ownership = discovery::prepare(router, segment).await?;
    let mut definitions = steps(segment);
    step::record_baseline(router, &mut definitions)
        .await
        .map_err(|source| SegmentError::StepFailed {
            step: "baseline".to_owned(),
            source: Box::new(source),
        })?;
    let mut applied = Vec::<&Step>::new();
    for definition in &definitions {
        if let Err(source) = step::apply(changes, router, definition, Direction::Create).await {
            let failed = rollback::may_have_changed_router(&source).then_some(definition);
            for rollback in failed.into_iter().chain(applied.into_iter().rev()) {
                if let Err(rollback_source) =
                    step::apply(changes, router, rollback, Direction::Delete).await
                {
                    return Err(SegmentError::RollbackFailed {
                        step: definition.name().to_owned(),
                        rollback_step: rollback.name().to_owned(),
                        source: Box::new(rollback_source),
                    });
                }
            }
            return Err(SegmentError::StepFailed {
                step: definition.name().to_owned(),
                source: Box::new(source),
            });
        }
        applied.push(definition);
        if definition.name() == "vlan-subinterface"
            && let Err(source) = ownership::persist(changes, router, segment.id, &ownership).await
        {
            step::apply(changes, router, definition, Direction::Delete)
                .await
                .map_err(|rollback| SegmentError::RollbackFailed {
                    step: "ownership".to_owned(),
                    rollback_step: definition.name().to_owned(),
                    source: Box::new(rollback),
                })?;
            return Err(SegmentError::StepFailed {
                step: "ownership".to_owned(),
                source: Box::new(source),
            });
        }
    }
    Ok(CreatedSegment { steps: definitions })
}

/// Reads complete and partial segments with persisted creation ownership.
#[expect(
    clippy::module_name_repetitions,
    reason = "read_segments is the requested public domain API"
)]
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_segments(router: &RouterCtx) -> Result<Vec<SegmentView>> {
    discovery::read(router).await
}

/// Deletes only the shared step definition belonging to an unchanged discovered segment.
// NOT cancel-safe: cancelled between delete steps, the segment is left partly deleted.
pub async fn delete_discovered(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    segment: &SegmentView,
) -> CoreResult<DeleteSummary, SegmentError> {
    let current = read_segments(router).await?;
    let found = current
        .iter()
        .find(|view| view.id == segment.id && view.same_ownership(segment))
        .ok_or(crate::DomainError::InvalidResponse)?;
    let summary = found.delete_summary();
    ownership::check_delete(router, found).await?;
    delete(
        changes,
        router,
        CreatedSegment {
            steps: found.steps(),
        },
    )
    .await?;
    Ok(summary)
}

/// Deletes one segment by executing the same step definition in reverse order.
// NOT cancel-safe: cancelled between delete steps, the segment is left partly deleted.
pub async fn delete(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    created: CreatedSegment,
) -> CoreResult<(), SegmentError> {
    for definition in created.steps.iter().rev() {
        step::apply(changes, router, definition, Direction::Delete)
            .await
            .map_err(|source| SegmentError::StepFailed {
                step: definition.name().to_owned(),
                source: Box::new(source),
            })?;
    }
    Ok(())
}

/// Builds one segment operation descriptor.
const fn operation(name: &'static str, path: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path: path,
        risk: Risk::Write,
        permission: Permission::Write,
        persists_immediately: false,
    }
}
