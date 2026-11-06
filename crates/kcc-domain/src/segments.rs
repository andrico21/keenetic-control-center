//! Reversible creation and deletion of UI-visible network segments.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "async multi-step workflow operations and planning functions are not inline candidates"
)]

mod step;

use core::{net::Ipv4Addr, result::Result as CoreResult};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_catalog::Risk;

use self::step::{Direction, Step, steps};
use crate::{ChangeOp, DomainDescriptor, DomainId, OperationDescriptor, Result, RouterCtx};

/// Complete input for one UI-visible network segment.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    read_ops: &[],
    write_ops: WRITES,
    required_components: &[],
};

/// Plans all validated create requests in execution order.
pub fn plan_create(router: &RouterCtx, segment: &SegmentSpec) -> Result<ChangeOp> {
    step::plan(router, &steps(segment), Direction::Create)
}

/// Plans all validated delete requests in reverse execution order.
pub fn plan_delete(router: &RouterCtx, segment: &SegmentSpec) -> Result<ChangeOp> {
    step::plan(router, &steps(segment), Direction::Delete)
}

/// Creates one segment, rolling applied steps back in reverse order on failure.
pub async fn create(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    segment: &SegmentSpec,
) -> CoreResult<CreatedSegment, SegmentError> {
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
            for rollback in applied.into_iter().rev() {
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
    }
    Ok(CreatedSegment { steps: definitions })
}

/// Deletes one segment by executing the same step definition in reverse order.
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
