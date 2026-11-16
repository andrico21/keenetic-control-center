//! `kcc_services_write`, `kcc_keendns_write`, and `kcc_router_users_write`.

use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, DomainError, RouterCtx, keendns,
    keendns::RemoteSecurityLevel,
    router_users,
    services::{self, HttpSslSetting, ManagementListener, SecurityLevel},
};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;

use super::common::{
    apply_cli, check_op, needed, open, own_logins, preauthorize_management, secret, text,
};
use crate::{KccMcp, McpFailure, domains::table::Area, support::route::parse};

/// Service write operations.
pub(super) const SERVICE_OPS: &[&str] = &[
    "set_service",
    "management_port",
    "management_security_level",
    "http_ssl",
];

/// KeenDNS write operations.
pub(super) const KEENDNS_OPS: &[&str] = &[
    "book_name",
    "drop_name",
    "proxy",
    "proxy_upstream",
    "cloud_security_level",
];

/// Router account write operations.
pub(super) const USER_OPS: &[&str] = &["create", "set_tag", "set_password", "delete"];

/// Arguments of the service, KeenDNS, and router-account write tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management change.
    #[serde(default)]
    confirm: bool,
    /// Service, KeenDNS name, proxy, or account name.
    #[serde(default)]
    name: Option<String>,
    /// Listener (`http`, `ssh`, `telnet`), security level, SSL setting (`enable`, `port`,
    /// `redirect`, `acme_get`, `acme_revoke`), domain, protocol, or tag.
    #[serde(default)]
    value: Option<String>,
    /// Upstream host for `proxy_upstream`.
    #[serde(default)]
    target: Option<String>,
    /// Port number.
    #[serde(default)]
    port: Option<u16>,
    /// Flag for enable operations.
    #[serde(default)]
    enabled: Option<bool>,
    /// Tags for a new account.
    #[serde(default)]
    tags: Vec<String>,
    /// New account password; never returned or logged.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    secret: Option<SecretString>,
}

/// Parses a management listener.
fn listener(value: Option<&str>) -> Result<ManagementListener, McpFailure> {
    Ok(match text(value)? {
        "http" => ManagementListener::Http,
        "ssh" => ManagementListener::Ssh,
        "telnet" => ManagementListener::Telnet,
        _ => return Err(McpFailure::InvalidArguments),
    })
}

/// Plans one service change.
fn plan_service(
    ctx: &RouterCtx,
    input: &AdminInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    Ok(match input.op.as_str() {
        "set_service" => {
            services::plan_service(ctx, text(input.name.as_deref())?, needed(input.enabled)?)
        }
        "management_port" => {
            services::plan_port(ctx, listener(input.name.as_deref())?, needed(input.port)?)
        }
        "management_security_level" => {
            let level = match text(input.value.as_deref())? {
                "public" => SecurityLevel::Public,
                "private" => SecurityLevel::Private,
                "protected" => SecurityLevel::Protected,
                _ => return Err(McpFailure::InvalidArguments),
            };
            services::plan_security_level(ctx, listener(input.name.as_deref())?, level)
        }
        _ => services::plan_http_ssl(
            ctx,
            match text(input.value.as_deref())? {
                "enable" => HttpSslSetting::Enable(needed(input.enabled)?),
                "port" => HttpSslSetting::Port(needed(input.port)?),
                "redirect" => HttpSslSetting::Redirect(needed(input.enabled)?),
                "acme_get" => HttpSslSetting::AcmeGet,
                "acme_revoke" => HttpSslSetting::AcmeRevoke,
                _ => return Err(McpFailure::InvalidArguments),
            },
        ),
    })
}

/// Plans one KeenDNS change.
fn plan_keendns(
    ctx: &RouterCtx,
    input: &AdminInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let name = || text(input.name.as_deref());
    let value = || text(input.value.as_deref());
    Ok(match input.op.as_str() {
        "book_name" => keendns::plan_book_name(ctx, name()?, value()?),
        "drop_name" => keendns::plan_drop_name(ctx, name()?, value()?),
        "proxy" => keendns::plan_proxy(ctx, name()?, needed(input.enabled)?),
        "proxy_upstream" => keendns::plan_proxy_upstream(
            ctx,
            name()?,
            value()?,
            text(input.target.as_deref())?,
            needed(input.port)?,
        ),
        _ => keendns::plan_cloud_security_level(
            ctx,
            match value()? {
                "public" => RemoteSecurityLevel::Public,
                "private" => RemoteSecurityLevel::Private,
                _ => return Err(McpFailure::InvalidArguments),
            },
        ),
    })
}

/// Runs one service or KeenDNS write.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn services_or_keendns(
    server: &KccMcp,
    area: Area,
    arguments: Value,
) -> Result<Value, McpFailure> {
    let input: AdminInput = parse(arguments)?;
    let services = area == Area::Services;
    check_op(if services { SERVICE_OPS } else { KEENDNS_OPS }, &input.op)?;
    if services
        && input.op == "set_service"
        && services::service_risk(text(input.name.as_deref())?) == Risk::Management
    {
        preauthorize_management(server, &input.host)?;
    }
    let opened = open(server, area, (input.host.clone(), &input.op, input.confirm)).await?;
    if services {
        let planned = plan_service(&opened.2, &input)?;
        apply_cli(
            server,
            &opened,
            (planned, input.confirm, services::change_request),
        )
        .await
    } else {
        let planned = plan_keendns(&opened.2, &input)?;
        apply_cli(
            server,
            &opened,
            (planned, input.confirm, keendns::change_request),
        )
        .await
    }
}

/// Runs one router-account write; the account the profile logs in with is protected.
pub(super) async fn router_users(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: AdminInput = parse(arguments)?;
    check_op(USER_OPS, &input.op)?;
    let opened = open(
        server,
        Area::RouterUsers,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let (_identity, router, ctx) = &opened;
    let name = text(input.name.as_deref())?;
    let planned = match input.op.as_str() {
        "create" => {
            let tags = input.tags.iter().map(String::as_str).collect::<Vec<_>>();
            router_users::plan_create(ctx, name, &tags)
        }
        "set_tag" => router_users::plan_tag(
            ctx,
            name,
            &own_logins(server, router.as_str())?,
            (text(input.value.as_deref())?, needed(input.enabled)?),
        ),
        "set_password" => router_users::plan_password(
            ctx,
            name,
            &own_logins(server, router.as_str())?,
            secret(input.secret)?,
        ),
        _ => router_users::plan_delete(ctx, name, &own_logins(server, router.as_str())?),
    };
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, router_users::change_request),
    )
    .await
}
