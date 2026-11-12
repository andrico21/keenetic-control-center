//! Client policy, DHCP pool and segment writes.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    clients::{self, Access, PolicySelection},
    dhcp::{self, model::PoolConfig},
    segments::{self, SegmentError, SegmentSpec},
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_dom_family::Family,
    args_dom_lan::{ClientsWriteCommand, DhcpWriteCommand, SegmentsWriteCommand, SelectionArgs},
    args_domains::{ClientsCommand, DhcpCommand, SegmentsCommand},
    change::{Gate, applied},
    context::Ctx,
    dom_core,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `clients` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn clients(
    ctx: &Ctx,
    command: Family<ClientsCommand, ClientsWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_core::clients(ctx, sub).await,
        Family::Writes(sub) => clients_writes(ctx, sub).await,
    }
}

/// Runs a client policy write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn clients_writes(ctx: &Ctx, command: ClientsWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let operation = match &command {
        ClientsWriteCommand::DefaultPolicy(chosen) => {
            clients::plan_default_policy(router, selection(chosen))?
        }
        ClientsWriteCommand::InterfacePolicy {
            interface,
            selection: chosen,
        } => clients::plan_interface_policy(router, interface, selection(chosen))?,
    };
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                clients::apply(changes, context, &operation).await?.unsaved,
            ))
        })
        .await
}

/// The hotspot policy chosen on the command line.
fn selection(args: &SelectionArgs) -> PolicySelection<'_> {
    match (args.permit, args.policy.as_deref()) {
        (true, _) => PolicySelection::Access(Access::Permit),
        (false, Some(name)) => PolicySelection::Policy(name),
        (false, None) => PolicySelection::Access(Access::Deny),
    }
}

/// Runs a `dhcp` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn dhcp(ctx: &Ctx, command: Family<DhcpCommand, DhcpWriteCommand>) -> Outcome {
    match command {
        Family::Base(sub) => dom_core::dhcp(ctx, sub).await,
        Family::Writes(sub) => dhcp_writes(ctx, sub).await,
    }
}

/// Runs a DHCP pool write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn dhcp_writes(ctx: &Ctx, command: DhcpWriteCommand) -> Outcome {
    let DhcpWriteCommand::Pool {
        name,
        begin,
        end,
        interface,
        gateway,
        dns,
        lease_seconds,
        state,
    } = command;
    let session = Session::open(ctx, Permission::Write).await?;
    let mut pool = PoolConfig::new(name, begin, end)
        .with_default_router(gateway.unwrap_or(begin))
        .with_dns_servers(dns)
        .with_lease_seconds(lease_seconds)
        .with_enabled(state.enabled());
    if let Some(value) = interface {
        pool = pool.with_interface(value);
    }
    let operation = dhcp::plan_pool(session.router(), &pool)?;
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                dhcp::apply(changes, context, &operation).await?.unsaved,
            ))
        })
        .await
}

/// Runs a `segments` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn segments(
    ctx: &Ctx,
    command: Family<SegmentsCommand, SegmentsWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_core::segments(ctx, sub).await,
        Family::Writes(sub) => segments_writes(ctx, sub).await,
    }
}

/// Runs a segment write through the stepwise segment executor.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: steps may apply before cancellation; failed steps roll back.
async fn segments_writes(ctx: &Ctx, command: SegmentsWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    match command {
        SegmentsWriteCommand::Create {
            id,
            vlan,
            address,
            mask,
            dhcp_begin,
            dhcp_end,
            ports,
            access_point,
            policy: connection_policy,
        } => {
            let mut spec = SegmentSpec::new(id, vlan, address, mask, dhcp_begin, dhcp_end, ports);
            if let Some(name) = access_point {
                spec = spec.with_access_point(name);
            }
            if let Some(name) = connection_policy {
                spec = spec.with_connection_policy(name);
            }
            let operation = segments::plan_create(session.router(), &spec).await?;
            let create_gate = Gate::new(operation.risk, operation.permission, false);
            session
                .change(create_gate, async |changes, context| {
                    drop(
                        segments::create(changes, context, &spec)
                            .await
                            .map_err(segment_failure)?,
                    );
                    Ok(json!({ "applied": true, "unsaved": true, "id": id }))
                })
                .await
        }
        SegmentsWriteCommand::Delete { id } => {
            let view = segments::read_segments(session.router())
                .await?
                .into_iter()
                .find(|segment| segment.id == id)
                .ok_or_else(|| {
                    Failure::message(
                        Exit::Usage,
                        keys::CLI_NOT_FOUND,
                        &[("name", &id.to_string())],
                    )
                })?;
            let operation = view.deletion_plan(session.router()).await?;
            let gate = Gate::new(operation.risk, operation.permission, false);
            session
                .change(gate, async |changes, context| {
                    drop(
                        segments::delete_discovered(changes, context, &view)
                            .await
                            .map_err(segment_failure)?,
                    );
                    Ok(json!({ "applied": true, "unsaved": true, "id": id }))
                })
                .await
        }
    }
}

/// Maps a stepwise segment failure; a failed rollback is a router error.
fn segment_failure(error: SegmentError) -> Failure {
    match error {
        SegmentError::Domain(domain) => Failure::from(domain),
        SegmentError::StepFailed { step: _, source } => Failure::from(*source),
        SegmentError::RollbackFailed {
            step: _,
            rollback_step: _,
            source: _,
        }
        | _ => Failure::text(Exit::Router, &error),
    }
}
