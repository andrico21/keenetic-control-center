//! Router login accounts and service tags.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "domain planning and asynchronous reads are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};

mod verification;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token::validate as validate_token,
};

/// One secret-free router account returned by `show rc user`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct RouterUser {
    /// Login name.
    pub name: Option<String>,
    /// Service-access tags.
    #[serde(rename = "tag")]
    pub tags: Vec<String>,
    /// Unmodelled non-secret fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Internal response shape that consumes password hashes before constructing the public model.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RawRouterUser {
    /// Login name.
    name: Option<String>,
    /// Service-access tags.
    #[serde(rename = "tag")]
    tags: Vec<String>,
    /// Password material is deliberately discarded at the read boundary.
    password: Option<Value>,
    /// Unmodelled non-secret fields.
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

/// User branch beneath the runtime configuration projection.
#[derive(Default, Deserialize)]
#[serde(default)]
struct UserProjection {
    /// Configured accounts.
    user: Vec<RawRouterUser>,
}

/// Router-user read inventory.
const READS: &[OperationDescriptor] = &[operation("list", "user", Risk::Read, Permission::Read)];

/// Router-user write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation("create", "user", Risk::Management, Permission::ManageUsers),
    operation(
        "set_tag",
        "user tag",
        Risk::Management,
        Permission::ManageUsers,
    ),
    operation(
        "set_password",
        "user password plain",
        Risk::Management,
        Permission::ManageUsers,
    ),
    operation("delete", "user", Risk::Management, Permission::ManageUsers),
];

/// Router-user domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::RouterUsers,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads router accounts while discarding password hashes at the response boundary.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_users(router: &RouterCtx) -> Result<Vec<RouterUser>> {
    let response = router.client.show_rc(json!({"user":{}})).await?;
    let projection =
        serde_json::from_value::<UserProjection>(response.configuration_tree().clone())
            .map_err(|_error| DomainError::InvalidResponse)?;
    Ok(projection
        .user
        .into_iter()
        .map(|raw| {
            let RawRouterUser {
                name,
                tags,
                password: _,
                extra,
            } = raw;
            RouterUser { name, tags, extra }
        })
        .collect())
}

/// Plans creation of a passwordless account and its initial tags.
pub fn plan_create(router: &RouterCtx, name: &str, tags: &[&str]) -> Result<ChangeOp> {
    validate_token(name)?;
    let mut requests = vec![validate(router, "user", &json!({"name":name}))?];
    for tag in tags {
        validate_token(tag)?;
        requests.push(validate(router, "user tag", &json!({"tag":tag}))?);
    }
    Ok(change(requests))
}

/// Plans adding or removing one account tag.
pub fn plan_tag(router: &RouterCtx, name: &str, tag: &str, enabled: bool) -> Result<ChangeOp> {
    validate_token(name)?;
    validate_token(tag)?;
    if name == "admin" && tag == "cli" && !enabled {
        return Err(DomainError::ProtectedAccount);
    }
    let tag_body = if enabled {
        json!({"tag":tag})
    } else {
        json!({"tag":tag,"no":true})
    };
    Ok(change(vec![
        validate(router, "user", &json!({"name":name}))?,
        validate(router, "user tag", &tag_body)?,
    ]))
}

/// Plans a plaintext password write whose printable plan retains only a redacted projection.
pub fn plan_password(
    router: &RouterCtx,
    name: &str,
    profile_login: &str,
    password: SecretString,
) -> Result<ChangeOp> {
    validate_token(name)?;
    if name == profile_login {
        return Err(DomainError::ProtectedAccount);
    }
    let user = validate(router, "user", &json!({"name":name}))?;
    let validated_password = router
        .catalog
        .validate_secret("user password plain", "password", password)
        .map_err(|issues| DomainError::Validation { issues })?;
    let mut verify = VerificationSpec::presence(
        vec!["show".to_owned(), "rc".to_owned(), "user".to_owned()],
        "/password/md5".to_owned(),
        PresencePredicate::LengthRange {
            minimum: 32,
            maximum: 32,
        },
    );
    verify.row = Some(("name".to_owned(), json!(name)));
    Ok(ChangeOp::new(
        vec![user, validated_password],
        vec![verify],
        Risk::Management,
        Permission::ManageUsers,
        false,
    ))
}

/// Plans deletion unless the account is the login used by the active router profile.
pub fn plan_delete(router: &RouterCtx, name: &str, profile_login: &str) -> Result<ChangeOp> {
    validate_token(name)?;
    if name == profile_login {
        return Err(DomainError::ProtectedAccount);
    }
    Ok(change(vec![validate(
        router,
        "user",
        &json!({"name":name,"no":true}),
    )?]))
}

/// Converts a user plan into the only workflow request permitted to execute it.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let first = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = first
        .value()
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let deleting = first.value().get("no").and_then(Value::as_bool) == Some(true);
    let mut commands = vec![ValidatedCli::new(
        if deleting {
            format!("no user {name}")
        } else {
            format!("user {name}")
        },
        first.clone(),
    )?];
    for request in operation.requests.iter().skip(1) {
        if request.path == "user password plain" {
            commands.push(
                ValidatedCli::from_template(
                    request.clone(),
                    &format!("user {name} password plain {{/password}}"),
                )
                .map_err(|_error| DomainError::InvalidResponse)?,
            );
            continue;
        }
        let tag = request
            .value()
            .get("tag")
            .and_then(Value::as_str)
            .ok_or(DomainError::InvalidResponse)?;
        let prefix = if request.value().get("no").and_then(Value::as_bool) == Some(true) {
            "no "
        } else {
            ""
        };
        commands.push(ValidatedCli::new(
            format!("{prefix}user {name} tag {tag}"),
            request.clone(),
        )?);
    }
    Ok(CliChangeRequest::new(
        commands,
        verification::specs(operation, name)?,
        operation.permission,
        json!({"operation":"router_user","login":name}),
    ))
}

/// Builds one operation descriptor.
const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
}

/// Validates one catalog request.
fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

/// Constructs the shared account-management operation shape.
const fn change(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Management,
        Permission::ManageUsers,
        false,
    )
}
