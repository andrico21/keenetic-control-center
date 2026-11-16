//! Read-back rows of the clients, KeenDNS, services and router-user domains.

use kcc_domain::{
    RouterCtx,
    clients::{self, Access, PolicySelection},
    keendns::{self, RemoteSecurityLevel},
    router_users,
    services::{self, ManagementListener, SecurityLevel},
};
use kcc_testkit::model::Firmware;

use super::model::{Check, Expect, Field, Row, Step, Steps};
use crate::support::toggle_service;

/// The clients, KeenDNS, services and router-user rows.
pub(crate) const ROWS: &[Row] = &[
    Row::new(
        "clients.silent_hotspot_policy",
        hotspot_policies_denying,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("policy"),
        },
    ),
    Row::new(
        "clients.hotspot_policies",
        hotspot_policies,
        Expect::Saved { after: None },
    ),
    Row::new(
        "keendns.silent_cloud_level",
        cloud_level,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("security-level"),
        },
    ),
    Row::new(
        "keendns.remote_settings",
        remote_settings,
        Expect::Saved { after: None },
    ),
    Row::new(
        "services.silent_toggle",
        service_toggle,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("service"),
        },
    ),
    Row::new(
        "services.silent_listener",
        listener_fields,
        Expect::Silent {
            path: "parse",
            field: Field::StartsWith("/ip/"),
        },
    ),
    Row::new(
        "services.listener",
        listener_fields,
        Expect::Saved { after: None },
    ),
    Row::new(
        "users.silent_account_create",
        account_create,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("user"),
        },
    ),
    Row::new(
        "users.account_and_tags",
        account_and_tags,
        Expect::Saved {
            after: Some(account_is_gone),
        },
    ),
];

/// The default and the interface policy, both denying.
fn hotspot_policies_denying(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let selection = PolicySelection::Access(Access::Deny);
        Ok(vec![
            Step::Clients(clients::plan_default_policy(ctx, selection)?),
            Step::Clients(clients::plan_interface_policy(ctx, "Bridge0", selection)?),
        ])
    })
}

/// A denying default policy and a permitting interface policy.
fn hotspot_policies(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        Ok(vec![
            Step::Clients(clients::plan_default_policy(
                ctx,
                PolicySelection::Access(Access::Deny),
            )?),
            Step::Clients(clients::plan_interface_policy(
                ctx,
                "Bridge0",
                PolicySelection::Access(Access::Permit),
            )?),
        ])
    })
}

/// The remote-access security level write.
fn cloud_level(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = keendns::plan_cloud_security_level(ctx, RemoteSecurityLevel::Private)?;
        Ok(vec![Step::Cli(keendns::change_request(&operation)?)])
    })
}

/// Security level, name booking, proxy and proxy upstream writes.
fn remote_settings(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operations = [
            keendns::plan_cloud_security_level(ctx, RemoteSecurityLevel::Private)?,
            keendns::plan_book_name(ctx, "readback67", "keenetic.link")?,
            keendns::plan_drop_name(ctx, "readback67", "keenetic.link")?,
            keendns::plan_proxy(ctx, "proxy67", true)?,
            keendns::plan_proxy_upstream(ctx, "proxy67", "http", "192.0.2.67", 8_080)?,
        ];
        let mut steps = Vec::new();
        for operation in &operations {
            steps.push(Step::Cli(keendns::change_request(operation)?));
        }
        Ok(steps)
    })
}

/// The toggle of the service the firmware's catalog documents.
fn service_toggle(ctx: &RouterCtx, firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = services::plan_service(ctx, toggle_service(firmware), true)?;
        Ok(vec![Step::Cli(services::change_request(&operation)?)])
    })
}

/// A management port (the one kcc already reaches the router on: moving it is refused) and
/// a management security level.
fn listener_fields(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let own_port = ctx
            .client
            .router_url()
            .port()
            .ok_or("origin without a port")?;
        let operations = [
            services::plan_port(ctx, ManagementListener::Http, own_port)?,
            services::plan_security_level(ctx, ManagementListener::Ssh, SecurityLevel::Protected)?,
        ];
        let mut steps = Vec::new();
        for operation in &operations {
            steps.push(Step::Cli(services::change_request(operation)?));
        }
        Ok(steps)
    })
}

/// A router account create.
fn account_create(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = router_users::plan_create(ctx, "readback67", &["http"])?;
        Ok(vec![Step::Cli(router_users::change_request(&operation)?)])
    })
}

/// Create, tag removal and deletion of one account.
fn account_and_tags(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operations = [
            router_users::plan_create(ctx, "readback67", &["http"])?,
            router_users::plan_tag(ctx, "readback67", "http", false)?,
            router_users::plan_delete(ctx, "readback67", "admin")?,
        ];
        let mut steps = Vec::new();
        for operation in &operations {
            steps.push(Step::Cli(router_users::change_request(operation)?));
        }
        Ok(steps)
    })
}

/// The deleted account is gone from the ordinary user read.
fn account_is_gone(ctx: &RouterCtx) -> Check<'_> {
    Box::pin(async move {
        let users = router_users::read_users(ctx).await?;
        Ok(!users
            .iter()
            .any(|row| row.name.as_deref() == Some("readback67")))
    })
}
