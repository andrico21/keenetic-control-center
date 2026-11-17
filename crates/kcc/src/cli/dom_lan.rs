//! DHCP and segment commands.

use kcc_app::permissions::Permission;
use kcc_domain::{
    dhcp::{self, model::PoolConfig},
    segments::{self, SegmentError, SegmentSpec},
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_dom_lan::{DhcpCommand, SegmentsCommand},
    args_domains::Toggle,
    change::{Gate, applied},
    context::Ctx,
    dom_clients::typed_mac,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `dhcp` command; replacing a pool without the options it would reset is
/// refused before anything is sent.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn dhcp(ctx: &Ctx, command: DhcpCommand) -> Outcome {
    let permission = match command {
        DhcpCommand::Pools
        | DhcpCommand::Leases
        | DhcpCommand::Bindings
        | DhcpCommand::Neighbours => Permission::Read,
        DhcpCommand::StaticLease { mac: _, address: _ }
        | DhcpCommand::Pool {
            name: _,
            begin: _,
            end: _,
            interface: _,
            gateway: _,
            dns: _,
            lease_seconds: _,
            state: _,
        } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        DhcpCommand::Pools => return session.show(&dhcp::read_pools(router).await?),
        DhcpCommand::Leases => return session.show(&dhcp::read_static_leases(router).await?),
        DhcpCommand::Bindings => return session.show(&dhcp::read_bindings(router).await?),
        DhcpCommand::Neighbours => return session.show(&dhcp::read_neighbours(router).await?),
        DhcpCommand::StaticLease { mac, address } => {
            dhcp::plan_static_lease(router, typed_mac(&mac)?, address).await?
        }
        DhcpCommand::Pool {
            name,
            begin,
            end,
            interface,
            gateway,
            dns,
            lease_seconds,
            state,
        } => {
            let missing = [
                ("--lease-seconds", lease_seconds.is_none()),
                ("--state", state.is_none()),
            ]
            .into_iter()
            .filter_map(|(flag, omitted)| omitted.then_some(flag))
            .collect::<Vec<_>>();
            refuse_partial_replacement(&session, &name, &missing).await?;
            let mut pool = PoolConfig::new(name, begin, end)
                .with_default_router(gateway)
                .with_lease_seconds(lease_seconds.unwrap_or(86_400))
                .with_enabled(state.is_none_or(Toggle::enabled));
            if !dns.is_empty() {
                pool = pool.with_dns_servers(dns);
            }
            if let Some(value) = interface {
                pool = pool.with_interface(value);
            }
            dhcp::plan_pool(router, &pool)?
        }
    };
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                dhcp::apply(changes, context, &operation).await?.unsaved,
            ))
        })
        .await
}

/// Refuses to replace the existing pool `name` while `missing` names the options the
/// replacement would reset.
///
/// # Errors
///
/// Returns a usage failure naming `missing`, or the read failure.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn refuse_partial_replacement(
    session: &Session<'_>,
    name: &str,
    missing: &[&str],
) -> Outcome {
    if !missing.is_empty()
        && dhcp::read_pools(session.router())
            .await?
            .iter()
            .any(|pool| pool.name.as_deref() == Some(name))
    {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_DHCP_POOL_REPLACE_NEEDS,
            &[("name", name), ("missing", &missing.join(", "))],
        ));
    }
    Ok(())
}

/// Runs a `segments` command; a write runs through the stepwise segment executor.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: steps may apply before cancellation; failed steps roll back.
pub(crate) async fn segments(ctx: &Ctx, command: SegmentsCommand) -> Outcome {
    let permission = match command {
        SegmentsCommand::List => Permission::Read,
        SegmentsCommand::Create {
            id: _,
            vlan: _,
            address: _,
            mask: _,
            dhcp_begin: _,
            dhcp_end: _,
            ports: _,
            access_point: _,
            policy: _,
        }
        | SegmentsCommand::Delete { id: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    match command {
        SegmentsCommand::List => session.show(&segments::read_segments(session.router()).await?),
        SegmentsCommand::Create {
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
        SegmentsCommand::Delete { id } => {
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
