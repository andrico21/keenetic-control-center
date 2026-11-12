//! KeenDNS, log, DNS, VPN, interface, internet connection, Wi-Fi and mesh commands.

use kcc_app::permissions::Permission;
use kcc_domain::{dns, interfaces, keendns, logging, mesh, vpn_clients, vpn_servers, wan};
use kcc_i18n::keys;
use kcc_rci::ObjectName;

use super::{
    args_domains_wire::{
        DnsCommand, InterfacesCommand, KeenDnsCommand, LogCommand, MeshCommand, VpnCommand,
        VpnServerCommand, WanCommand,
    },
    change::{Gate, applied},
    context::Ctx,
    dom_net::new_secret,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `keendns` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn keendns(ctx: &Ctx, command: KeenDnsCommand) -> Outcome {
    if matches!(command, KeenDnsCommand::Status) {
        let session = Session::open(ctx, Permission::Read).await?;
        return session.show(&keendns::read_status(session.router()).await?);
    }
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let operation = match command {
        KeenDnsCommand::Status => return Ok(()),
        KeenDnsCommand::Book { name, domain } => keendns::plan_book_name(router, &name, &domain)?,
        KeenDnsCommand::Drop { name, domain } => keendns::plan_drop_name(router, &name, &domain)?,
        KeenDnsCommand::Proxy { name, state } => {
            keendns::plan_proxy(router, &name, state.enabled())?
        }
    };
    session
        .cli(&operation, keendns::change_request(&operation)?)
        .await
}

/// Runs a `log` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn log(ctx: &Ctx, command: LogCommand) -> Outcome {
    let permission = match command {
        LogCommand::Read { lines: _ } => Permission::Read,
        LogCommand::Clear => Permission::Destructive,
        LogCommand::Server {
            address: _,
            port: _,
            state: _,
        }
        | LogCommand::Reduction { state: _ }
        | LogCommand::Suppress { ident: _, state: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        LogCommand::Read { lines } => {
            return session.show(&logging::read_log(router, lines).await?);
        }
        LogCommand::Server {
            address,
            port,
            state,
        } => logging::plan_server(router, &address, port, state.enabled())?,
        LogCommand::Reduction { state } => logging::plan_reduction(router, state.enabled())?,
        LogCommand::Suppress { ident, state } => {
            logging::plan_suppress(router, &ident, state.enabled())?
        }
        LogCommand::Clear => {
            let target = session.target();
            logging::plan_clear(router, target.id(), target.role(), true)?
        }
    };
    session
        .cli(&operation, logging::change_request(&operation)?)
        .await
}

/// Runs a `dns` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn dns(ctx: &Ctx, command: DnsCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Read).await?;
    match command {
        DnsCommand::Proxy => session.show(&dns::read_dns_proxy(session.router()).await?),
        DnsCommand::Config => session.show(&dns::read_configuration(session.router()).await?),
    }
}

/// Runs a `vpn` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn vpn(ctx: &Ctx, command: VpnCommand) -> Outcome {
    let VpnCommand::List = command;
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&vpn_clients::read_clients(session.router()).await?)
}

/// Runs a `vpn-server` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn vpn_server(ctx: &Ctx, command: VpnServerCommand) -> Outcome {
    let VpnServerCommand::Status = command;
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&vpn_servers::read_servers(session.router()).await?)
}

/// Runs an `interfaces` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn interfaces(ctx: &Ctx, command: InterfacesCommand) -> Outcome {
    let permission = match command {
        InterfacesCommand::List
        | InterfacesCommand::Show { name: _ }
        | InterfacesCommand::Stats => Permission::Read,
        InterfacesCommand::Up { name: _ }
        | InterfacesCommand::Down { name: _ }
        | InterfacesCommand::Description { name: _, text: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let (name, operation) = match command {
        InterfacesCommand::List => {
            return session.show(&interfaces::read_interfaces(router).await?);
        }
        InterfacesCommand::Stats => {
            return session.show(&interfaces::read_statistics(router).await?);
        }
        InterfacesCommand::Show { name } => {
            return session.show(&interfaces::read_interface(router, &object(&name)?).await?);
        }
        InterfacesCommand::Up { name } => {
            let object_name = object(&name)?;
            let operation = interfaces::plan_up(router, &object_name)?;
            (object_name, operation)
        }
        InterfacesCommand::Down { name } => {
            let object_name = object(&name)?;
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let operation = interfaces::plan_down(router, &object_name, verdict)?;
            (object_name, operation)
        }
        InterfacesCommand::Description { name, text } => {
            let object_name = object(&name)?;
            let operation = interfaces::plan_description(router, &object_name, &text)?;
            (object_name, operation)
        }
    };
    let gate = Gate::of(&operation).self_bracketed();
    session
        .change(gate, async |changes, context| {
            let result = interfaces::apply(changes, context, &name, operation, true)
                .await
                .map_err(Failure::from)?;
            Ok(applied(result.unsaved))
        })
        .await
}

/// Runs a `wan` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn wan(ctx: &Ctx, command: WanCommand) -> Outcome {
    if matches!(command, WanCommand::List) {
        let session = Session::open(ctx, Permission::Read).await?;
        return session.show(&wan::read_connections(session.router()).await?);
    }
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let (name, operation) = match command {
        WanCommand::List => return Ok(()),
        WanCommand::Identity { name, identity } => {
            let object_name = object(&name)?;
            let operation = wan::plan_identity(router, &object_name, &identity)?;
            (object_name, operation)
        }
        WanCommand::Password { name } => {
            let object_name = object(&name)?;
            let operation = wan::plan_password(router, &object_name, new_secret(ctx, &name)?)?;
            (object_name, operation)
        }
        WanCommand::Priority { name, value } => {
            let object_name = object(&name)?;
            let operation = wan::plan_priority(router, &object_name, value).await?;
            (object_name, operation)
        }
        WanCommand::Mtu { name, value } => {
            let object_name = object(&name)?;
            let operation = wan::plan_mtu(router, &object_name, value)?;
            (object_name, operation)
        }
        WanCommand::DefaultRoute { name, state } => {
            let object_name = object(&name)?;
            let operation = wan::plan_default_route(router, &object_name, state.enabled())?;
            (object_name, operation)
        }
    };
    session
        .cli(&operation, wan::change_request(&name, &operation)?)
        .await
}

/// Runs a `mesh` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn mesh(ctx: &Ctx, command: MeshCommand) -> Outcome {
    let permission = match command {
        MeshCommand::Members | MeshCommand::Associations => Permission::Read,
        MeshCommand::UpdateCheck { member: _ } | MeshCommand::UpdateStart { member: _ } => {
            Permission::Write
        }
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        MeshCommand::Members => return session.show(&mesh::read_members(router).await?),
        MeshCommand::Associations => return session.show(&mesh::read_associations(router).await?),
        MeshCommand::UpdateCheck { member } => mesh::plan_update_check(router, &member)?,
        MeshCommand::UpdateStart { member } => mesh::plan_update_start(router, &member)?,
    };
    session
        .cli(&operation, mesh::change_request(&operation)?)
        .await
}

/// Parses a router object name, e.g. `Bridge0` or `WifiMaster0/AccessPoint0`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
pub(crate) fn object(name: &str) -> Outcome<ObjectName> {
    name.parse().map_err(|_error| {
        Failure::message(Exit::Validation, keys::CLI_NOT_FOUND, &[("name", name)])
    })
}
