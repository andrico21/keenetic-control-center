//! One reversible write per domain, verified by a fresh read and reverted by its inverse.

use core::error::Error;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand},
};
use kcc_catalog::HttpMethod;
use kcc_domain::{DomainId, RouterCtx, interfaces, schedules};
use kcc_rci::ObjectName;
use serde_json::json;

use super::{safety, writes_net};

/// Description written to the probed interface.
const DESCRIPTION: &str = "kcc-live-51";

/// Schedule created and deleted by the suite.
const SCHEDULE: &str = "kcclive51";

/// How one domain's write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteResult {
    /// Applied, read back, reverted, and the revert read back.
    Reverted,
    /// Applied and read back, then deliberately left applied (mutation check only).
    LeftApplied,
    /// No safe reversible write exists for the domain or the router; the reason says why.
    Skipped(&'static str),
}

/// One domain's write outcome.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteOutcome {
    /// Domain.
    pub domain: DomainId,
    /// Result.
    pub result: WriteResult,
}

/// Inputs of one domain write.
pub(crate) struct Writer<'writer> {
    /// The suite's change set.
    pub changes: &'writer mut ChangeSet,
    /// Domain context for planning and fresh reads.
    pub ctx: &'writer RouterCtx,
    /// Normalized running configuration at suite start.
    pub running: &'writer str,
    /// Whether to revert after the read-back.
    pub revert: bool,
}

impl Writer<'_> {
    /// The result after a verified write, honouring the revert flag.
    pub(crate) const fn done(&self) -> WriteResult {
        if self.revert {
            WriteResult::Reverted
        } else {
            WriteResult::LeftApplied
        }
    }
}

/// Runs the reversible write of `domain`, or names why the domain has none.
///
/// # Errors
/// Returns planning, workflow or read-back failures.
// NOT cancel-safe: mutates the router under the fail-safe timer.
pub(crate) async fn exercise(
    writer: &mut Writer<'_>,
    domain: DomainId,
) -> Result<WriteResult, Box<dyn Error>> {
    match domain {
        DomainId::Interfaces => interface_description(writer).await,
        DomainId::Schedules => schedule(writer).await,
        DomainId::Routing => writes_net::static_route(writer).await,
        DomainId::Nat => writes_net::port_forward(writer).await,
        DomainId::Clients => writes_net::known_host(writer).await,
        DomainId::System
        | DomainId::Internet
        | DomainId::Configuration
        | DomainId::Diagnostics
        | DomainId::Dhcp
        | DomainId::Segments
        | DomainId::RouterUsers
        | DomainId::Policies
        | DomainId::Firewall
        | DomainId::Services
        | DomainId::Components
        | DomainId::Storage
        | DomainId::KeenDns
        | DomainId::Logging
        | DomainId::Dns
        | DomainId::VpnClients
        | DomainId::VpnServers
        | DomainId::Wan
        | DomainId::Wifi
        | DomainId::Mesh
        | _ => Ok(WriteResult::Skipped(no_write_reason(domain))),
    }
}

/// Why a domain has no write in this suite.
const fn no_write_reason(domain: DomainId) -> &'static str {
    match domain {
        DomainId::System => "identity, clock and NTP writes affect every client",
        DomainId::Internet => "ping-check writes change WAN failover",
        DomainId::Configuration => "save, commit and rollback are the safety net itself",
        DomainId::Diagnostics => "diagnostic jobs send traffic and change no configuration",
        DomainId::Dhcp => "pool and lease writes can hand out conflicting addresses",
        DomainId::Segments => "segment writes create bridges and DHCP pools together",
        DomainId::RouterUsers => "account writes can lock out the suite's own login",
        DomainId::Policies => "connection-policy writes re-route clients",
        DomainId::Firewall => "access-list writes can cut the management connection",
        DomainId::Services => "service writes can drop the management listener",
        DomainId::Components => "component writes reboot the router",
        DomainId::Storage => "eject and maintenance act on attached disks",
        DomainId::KeenDns => "name booking is registered in the vendor cloud",
        DomainId::Logging => "log writes discard or redirect router logs",
        DomainId::Dns => "DNS writes change every client's name resolution",
        DomainId::VpnClients => "VPN client writes re-route policy clients",
        DomainId::VpnServers => "VPN server writes open WAN listeners",
        DomainId::Wan => "WAN writes can drop the internet connection",
        DomainId::Wifi => "Wi-Fi writes disconnect wireless clients",
        DomainId::Mesh => "mesh writes act on member nodes",
        DomainId::Clients
        | DomainId::Routing
        | DomainId::Nat
        | DomainId::Schedules
        | DomainId::Interfaces
        | _ => "no reversible write is defined for this domain",
    }
}

/// The interface named by `interface <name>` whose block in `running` holds a description,
/// skipping `default_gateway`, with that description.
fn described_interface(running: &str, default_gateway: Option<&str>) -> Option<(String, String)> {
    let mut current = None;
    for line in running.lines() {
        if let Some(name) = line.strip_prefix("interface ") {
            current = Some(name.trim().to_owned());
            continue;
        }
        if !line.starts_with(' ') {
            current = None;
            continue;
        }
        if let (Some(name), Some(text)) = (&current, line.trim().strip_prefix("description "))
            && Some(name.as_str()) != default_gateway
        {
            return Some((name.clone(), text.trim_matches('"').to_owned()));
        }
    }
    None
}

/// Sets an interface description, reads it back, then restores the original.
// NOT cancel-safe: mutates the router.
async fn interface_description(writer: &mut Writer<'_>) -> Result<WriteResult, Box<dyn Error>> {
    let gateway = writes_net::default_gateway(writer.ctx).await?;
    let Some((found, original)) = described_interface(writer.running, gateway.as_deref()) else {
        return Ok(WriteResult::Skipped(
            "no non-default interface has a description",
        ));
    };
    let name = ObjectName::try_from(found)?;
    for (value, last) in [(DESCRIPTION, !writer.revert), (original.as_str(), true)] {
        let operation = interfaces::plan_description(writer.ctx, &name, value)?;
        drop(interfaces::apply(writer.changes, &name, &operation).await?);
        let fresh = interfaces::read_interface(writer.ctx, &name).await?;
        if fresh.description.as_deref() != Some(value) {
            return Err(format!("interface description read-back failed on {name}").into());
        }
        if last {
            break;
        }
    }
    Ok(writer.done())
}

/// Whether a fresh running configuration declares the probe schedule.
// cancel-safe: one read.
async fn schedule_present(ctx: &RouterCtx) -> Result<bool, Box<dyn Error>> {
    let running = safety::snapshot(&ctx.client).await?;
    let header = format!("schedule {SCHEDULE}");
    Ok(running.lines().any(|line| line.trim_end() == header))
}

/// Creates a schedule, reads it back from a fresh running configuration (`show schedule`
/// reports runtime state only), then deletes it with `no schedule`.
// NOT cancel-safe: mutates the router.
async fn schedule(writer: &mut Writer<'_>) -> Result<WriteResult, Box<dyn Error>> {
    if schedule_present(writer.ctx).await? {
        return Ok(WriteResult::Skipped("the probe schedule already exists"));
    }
    let create = schedules::plan_create(writer.ctx, SCHEDULE)?;
    drop(
        writer
            .changes
            .apply_cli(schedules::change_request(&create)?)
            .await?,
    );
    if !schedule_present(writer.ctx).await? {
        return Err("schedule read-back failed".into());
    }
    if !writer.revert {
        return Ok(writer.done());
    }
    let checked = writer.ctx.catalog.validate(
        "schedule",
        HttpMethod::Post,
        &json!({"name": SCHEDULE, "no": true}),
    );
    let validated = checked.map_err(|issues| format!("no schedule invalid: {issues:?}"))?;
    let delete = CliChangeRequest::new(
        vec![CliCommand::new(
            format!("no schedule {SCHEDULE}"),
            validated,
        )?],
        Vec::new(),
        Permission::Write,
        json!({"operation": "schedule", "name": SCHEDULE}),
    );
    drop(writer.changes.apply_cli(delete).await?);
    if schedule_present(writer.ctx).await? {
        return Err("schedule deletion read-back failed".into());
    }
    Ok(writer.done())
}
