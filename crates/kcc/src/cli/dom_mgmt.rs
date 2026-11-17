//! Service and KeenDNS commands; their management-risk writes run inside the fail-safe
//! timer and need `--yes`.

use kcc_app::permissions::Permission;
use kcc_domain::{
    DomainError,
    configuration::SafetyNet,
    keendns::{self, RemoteSecurityLevel},
    services::{self, HttpSslSetting, ManagementListener, SecurityLevel},
};
use kcc_i18n::keys;

use super::{
    args_dom_admin::{
        CloudLevelChoice, HttpsChoice, KeenDnsCommand, LevelChoice, ListenerChoice,
        ServicesCommand, UpstreamChoice,
    },
    context::Ctx,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `services` command; the listener changes are management changes.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn services(ctx: &Ctx, command: ServicesCommand) -> Outcome {
    let permissions = match &command {
        ServicesCommand::List => vec![Permission::Read],
        ServicesCommand::Set { name, state: _ } => {
            SafetyNet::required(Permission::Write, services::service_risk(name))
        }
        ServicesCommand::Port {
            listener: _,
            port: _,
        }
        | ServicesCommand::SecurityLevel {
            listener: _,
            level: _,
        }
        | ServicesCommand::Https {
            setting: _,
            port: _,
        } => vec![Permission::Write],
    };
    let session = Session::open_permissions(ctx, &permissions).await?;
    let router = session.router();
    let listener = |choice| match choice {
        ListenerChoice::Http => ManagementListener::Http,
        ListenerChoice::Ssh => ManagementListener::Ssh,
        ListenerChoice::Telnet => ManagementListener::Telnet,
    };
    let operation = match command {
        ServicesCommand::List => return session.show(&services::read_services(router).await?),
        ServicesCommand::Set { name, state } => {
            services::plan_service(router, &name, state.enabled())?
        }
        ServicesCommand::Port {
            listener: which,
            port,
        } => services::plan_port(router, listener(which), port).map_err(own_listener)?,
        ServicesCommand::SecurityLevel {
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
        ServicesCommand::Https { setting, port } => {
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

/// Runs a `keendns` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn keendns(ctx: &Ctx, command: KeenDnsCommand) -> Outcome {
    let permission = match command {
        KeenDnsCommand::Status => Permission::Read,
        KeenDnsCommand::Book { name: _, domain: _ }
        | KeenDnsCommand::Drop { name: _, domain: _ }
        | KeenDnsCommand::Proxy { name: _, state: _ }
        | KeenDnsCommand::ProxyUpstream {
            name: _,
            protocol: _,
            host: _,
            port: _,
        }
        | KeenDnsCommand::CloudLevel { level: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        KeenDnsCommand::Status => return session.show(&keendns::read_status(router).await?),
        KeenDnsCommand::Book { name, domain } => keendns::plan_book_name(router, &name, &domain)?,
        KeenDnsCommand::Drop { name, domain } => keendns::plan_drop_name(router, &name, &domain)?,
        KeenDnsCommand::Proxy { name, state } => {
            keendns::plan_proxy(router, &name, state.enabled())?
        }
        KeenDnsCommand::ProxyUpstream {
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
        KeenDnsCommand::CloudLevel { level } => {
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
