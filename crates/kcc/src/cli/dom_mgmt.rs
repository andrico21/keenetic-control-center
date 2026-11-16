//! Management-risk writes of the service and KeenDNS domains; each runs inside the
//! fail-safe timer and needs `--yes`.

use kcc_app::permissions::Permission;
use kcc_domain::{
    DomainError,
    keendns::{self, RemoteSecurityLevel},
    services::{self, HttpSslSetting, ManagementListener, SecurityLevel},
};
use kcc_i18n::keys;

use super::{
    args_dom_admin::{
        CloudLevelChoice, HttpsChoice, KeenDnsWriteCommand, LevelChoice, ListenerChoice,
        ServicesWriteCommand, UpstreamChoice,
    },
    args_dom_family::Family,
    args_domains_net::ServicesCommand,
    args_domains_wire::KeenDnsCommand,
    context::Ctx,
    dom_net, dom_wire,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `services` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn services(
    ctx: &Ctx,
    command: Family<ServicesCommand, ServicesWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_net::services(ctx, sub).await,
        Family::Writes(sub) => services_writes(ctx, sub).await,
    }
}

/// Runs a management-listener write inside the fail-safe timer.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn services_writes(ctx: &Ctx, command: ServicesWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let listener = |choice| match choice {
        ListenerChoice::Http => ManagementListener::Http,
        ListenerChoice::Ssh => ManagementListener::Ssh,
        ListenerChoice::Telnet => ManagementListener::Telnet,
    };
    let operation = match command {
        ServicesWriteCommand::Port {
            listener: which,
            port,
        } => services::plan_port(router, listener(which), port).map_err(own_listener)?,
        ServicesWriteCommand::SecurityLevel {
            listener: which,
            level,
        } => {
            let zone = match level {
                LevelChoice::Public => SecurityLevel::Public,
                LevelChoice::Private => SecurityLevel::Private,
                LevelChoice::Protected => SecurityLevel::Protected,
            };
            services::plan_security_level(router, listener(which), zone)?
        }
        ServicesWriteCommand::Https { setting, port } => {
            let ssl = match setting {
                HttpsChoice::On => HttpSslSetting::Enable(true),
                HttpsChoice::Off => HttpSslSetting::Enable(false),
                HttpsChoice::Port => HttpSslSetting::Port(port.unwrap_or_default()),
                HttpsChoice::Redirect => HttpSslSetting::Redirect(true),
                HttpsChoice::NoRedirect => HttpSslSetting::Redirect(false),
                HttpsChoice::AcmeGet => HttpSslSetting::AcmeGet,
                HttpsChoice::AcmeRevoke => HttpSslSetting::AcmeRevoke,
            };
            services::plan_http_ssl(router, ssl).map_err(own_listener)?
        }
    };
    session
        .cli(&operation, services::change_request(&operation)?)
        .await
}

/// The planner's refusal to change the listener the router profile's URL uses, in words.
fn own_listener(error: DomainError) -> Failure {
    if matches!(error, DomainError::ProtectedAccount) {
        Failure::message(Exit::Policy, keys::CLI_LISTENER_IN_USE, &[])
    } else {
        error.into()
    }
}

/// Runs a `keendns` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn keendns(
    ctx: &Ctx,
    command: Family<KeenDnsCommand, KeenDnsWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_wire::keendns(ctx, sub).await,
        Family::Writes(sub) => keendns_writes(ctx, sub).await,
    }
}

/// Runs a KeenDNS management write inside the fail-safe timer.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn keendns_writes(ctx: &Ctx, command: KeenDnsWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let operation = match command {
        KeenDnsWriteCommand::ProxyUpstream {
            name,
            protocol,
            host,
            port,
        } => {
            let scheme = match protocol {
                UpstreamChoice::Http => "http",
                UpstreamChoice::Https => "https",
                UpstreamChoice::Connect => "connect",
            };
            keendns::plan_proxy_upstream(router, &name, scheme, &host, port)?
        }
        KeenDnsWriteCommand::CloudLevel { level } => {
            let exposure = match level {
                CloudLevelChoice::Public => RemoteSecurityLevel::Public,
                CloudLevelChoice::Private => RemoteSecurityLevel::Private,
            };
            keendns::plan_cloud_security_level(router, exposure)?
        }
    };
    session
        .cli(&operation, keendns::change_request(&operation)?)
        .await
}
