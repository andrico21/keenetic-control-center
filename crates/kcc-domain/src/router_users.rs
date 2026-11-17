//! Router login accounts and service tags.

use alloc::{collections::BTreeMap, vec};

pub mod protection;
mod verification;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::{Risk, ValidatedRequest};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use self::protection::OwnLogins;
use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token::validate as validate_token, descriptor, planning::validate,
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
const READS: &[OperationDescriptor] = &[descriptor::operation(
    "list",
    "user",
    Risk::Read,
    Permission::Read,
)];

/// Router-user write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::operation("create", "user", Risk::Management, Permission::ManageUsers),
    descriptor::operation(
        "set_tag",
        "user tag",
        Risk::Management,
        Permission::ManageUsers,
    ),
    descriptor::operation(
        "set_password",
        "user password plain",
        Risk::Management,
        Permission::ManageUsers,
    ),
    descriptor::operation("delete", "user", Risk::Management, Permission::ManageUsers),
];

/// Router-user domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::RouterUsers,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads router accounts while discarding password hashes at the response boundary.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// cancel-safe: a single read request; cancellation changes nothing on the router.
#[inline]
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
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_create(router: &RouterCtx, name: &str, tags: &[&str]) -> Result<ChangeOp> {
    validate_token(name)?;
    let mut requests = vec![validate(router, "user", &json!({"name":name}))?];
    for tag in tags {
        validate_token(tag)?;
        requests.push(validate(router, "user tag", &json!({"tag":tag}))?);
    }
    Ok(change(requests))
}

/// Plans adding or removing one account tag; removing a tag from an account kcc signs in
/// with is refused, as is removing `cli` from `admin`.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), when the change would cut kcc off from the router
/// ([`DomainError::ProtectedAccount`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_tag(
    router: &RouterCtx,
    name: &str,
    own: &OwnLogins,
    (tag, enabled): (&str, bool),
) -> Result<ChangeOp> {
    validate_token(name)?;
    validate_token(tag)?;
    if !enabled {
        own.guard(name)?;
    }
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
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_password(
    router: &RouterCtx,
    name: &str,
    own: &OwnLogins,
    password: SecretString,
) -> Result<ChangeOp> {
    validate_token(name)?;
    own.guard(name)?;
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

/// Plans deletion unless kcc signs in with the account.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_delete(router: &RouterCtx, name: &str, own: &OwnLogins) -> Result<ChangeOp> {
    validate_token(name)?;
    own.guard(name)?;
    Ok(change(vec![validate(
        router,
        "user",
        &json!({"name":name,"no":true}),
    )?]))
}

/// Converts a user plan into the only workflow request permitted to execute it.
///
/// # Errors
///
/// Returns an error when the plan holds no request, a request lacks its login name or tag,
/// the password request cannot be rendered, or its read-back cannot be built
/// ([`DomainError::InvalidResponse`]), or when a rendered line does not bind to its request
/// ([`DomainError::Workflow`]).
#[inline]
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
