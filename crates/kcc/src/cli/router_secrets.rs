//! `router add` and `router edit`.
//!
//! Every credential they take is read once, sealed under the master key and referenced
//! only through its sealed record.

use kcc_app::{
    credentials::{CredentialError, CredentialKind, CredentialStore},
    permissions::Permission,
    registry::{ManagedRouterProfile, ProfileSource, RegistryError},
    settings::{RouterAuth, RouterTls},
};
use kcc_i18n::{bundle::MessageKey, keys};
use secrecy::SecretString;
use serde_json::{Value, json};

use super::{
    args_router::{AddArgs, CredentialArgs, EditArgs},
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    outbound, router_edit,
    routers::parse_url,
    secret::read_secret,
};

/// Secrets given in one command, each with its kind.
pub(super) type Secrets = Vec<(CredentialKind, SecretString)>;

/// Adds a router profile whose credentials are sealed.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes the profile and its sealed records.
pub(crate) async fn add(ctx: &Ctx, services: &Services, args: AddArgs) -> Outcome {
    let role = ctx
        .principal()
        .authorize(&[Permission::ManageRouters], &[&args.id])?;
    let url = parse_url(&args.url)?;
    let auth = args
        .credentials
        .auth
        .map_or(RouterAuth::Auto, RouterAuth::from);
    if args.credentials.token_file.is_some() && auth != RouterAuth::Token {
        return Err(usage(keys::CLI_ROUTER_TOKEN_NEEDS_TOKEN_AUTH, &[]));
    }
    if args.credentials.read_password_file.is_some() && args.credentials.read_login.is_none() {
        return Err(usage(keys::CLI_ROUTER_READ_NEEDS_LOGIN, &[]));
    }
    outbound::check(services.registry(), &url).await?;
    let id = args.id;
    let primary = if auth == RouterAuth::Token {
        CredentialKind::Token
    } else {
        CredentialKind::Password
    };
    let mut secrets = vec![(primary, secret(ctx, &id, primary, &args.credentials)?)];
    if args.credentials.read_login.is_some() {
        let kind = CredentialKind::ReadPassword;
        secrets.push((kind, secret(ctx, &id, kind, &args.credentials)?));
    }
    let store = services.credentials();
    let mut profile = ManagedRouterProfile::new(
        id.clone(),
        url,
        args.login,
        store.sealed_path(&id, CredentialKind::Password)?,
    );
    profile.tags = args.tags;
    profile.test_device = args.test_device;
    profile.tls = args
        .pin_sha256
        .map_or(RouterTls::Verify, RouterTls::PinSha256);
    profile.auth = auth;
    profile.read_login = args.credentials.read_login;
    point(store, &mut profile, &secrets)?;
    services.registry().create(&role, profile).await?;
    if let Err(error) = seal(store, &id, &secrets) {
        drop(services.registry().delete(&role, &id).await);
        drop(store.remove(&id));
        return Err(error.into());
    }
    let kinds = secrets.iter().map(|(kind, _)| *kind).collect::<Vec<_>>();
    ctx.audit(
        services,
        "cli.router_add",
        Some(&id),
        audited(&kinds),
        "success",
    )
    .await;
    let out = ctx.out();
    out.emit(
        &json!({ "id": id, "added": true }),
        &out.tr(keys::CLI_ROUTER_ADDED, &[("name", &id)]),
    )
}

/// Changes a router profile; a moved endpoint needs the primary credential again.
///
/// # Errors
///
/// Returns the command's failure with its exit code; a refused change writes nothing.
// NOT cancel-safe: writes the profile and its sealed records.
pub(crate) async fn edit(ctx: &Ctx, services: &Services, args: EditArgs) -> Outcome {
    let role = ctx
        .principal()
        .authorize(&[Permission::ManageRouters], &[&args.id])?;
    let entry = services.registry().get(&args.id)?;
    if !matches!(entry.source, ProfileSource::State) {
        return Err(RegistryError::ConfigDefined { id: args.id }.into());
    }
    let id = args.id.clone();
    let plan = router_edit::plan(&entry.profile, args)?;
    let mut secrets = Secrets::new();
    for kind in plan.given() {
        secrets.push((*kind, secret(ctx, &id, *kind, plan.inputs())?));
    }
    let store = services.credentials();
    let (mut profile, removed, changed) = plan.into_parts();
    point(store, &mut profile, &secrets)?;
    seal(store, &id, &secrets)?;
    services.registry().update(&role, profile).await?;
    for kind in removed {
        store.remove_kind(&id, kind)?;
    }
    ctx.audit(
        services,
        "cli.router_edit",
        Some(&id),
        audited(&changed),
        "success",
    )
    .await;
    let out = ctx.out();
    out.emit(
        &json!({ "id": id, "updated": true }),
        &out.tr(keys::CLI_ROUTER_UPDATED, &[("name", &id)]),
    )
}

/// Reads the secret of `kind` from its input file, else `KCC_PASSWORD` or a prompt.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn secret(
    ctx: &Ctx,
    id: &str,
    kind: CredentialKind,
    inputs: &CredentialArgs,
) -> Outcome<SecretString> {
    let (file, prompt) = match kind {
        CredentialKind::Token => (inputs.token_file.as_deref(), keys::CLI_PROMPT_ROUTER_TOKEN),
        CredentialKind::ReadPassword => (
            inputs.read_password_file.as_deref(),
            keys::CLI_PROMPT_ROUTER_READ_PASSWORD,
        ),
        CredentialKind::Password | _ => (
            ctx.globals().password_file(),
            keys::CLI_PROMPT_ROUTER_PASSWORD,
        ),
    };
    read_secret(file, &ctx.out().tr(prompt, &[("router", id)]))
}

/// Points `profile` at the sealed record of every given kind; a primary credential of
/// one kind replaces the other.
///
/// # Errors
///
/// Returns a credential path failure.
fn point(
    store: &CredentialStore,
    profile: &mut ManagedRouterProfile,
    secrets: &Secrets,
) -> Outcome {
    for (kind, _) in secrets {
        let sealed = Some(store.sealed_path(&profile.id, *kind)?);
        match kind {
            CredentialKind::Token => {
                profile.token_file = sealed;
                profile.password_file = None;
            }
            CredentialKind::ReadPassword => profile.read_password_file = sealed,
            CredentialKind::Password | _ => {
                profile.password_file = sealed;
                profile.token_file = None;
            }
        }
    }
    Ok(())
}

/// Seals every given secret.
///
/// # Errors
///
/// Returns the first storage or encryption failure.
fn seal(store: &CredentialStore, id: &str, secrets: &Secrets) -> Result<(), CredentialError> {
    secrets
        .iter()
        .try_for_each(|(kind, secret)| store.store(id, *kind, secret))
}

/// The audit parameters naming the changed credential kinds, never their values.
fn audited(kinds: &[CredentialKind]) -> Value {
    let names = CredentialKind::ALL
        .into_iter()
        .filter(|kind| kinds.contains(kind))
        .map(CredentialKind::audit_name)
        .collect::<Vec<_>>();
    json!({ "credentials": names })
}

/// A usage refusal (exit 2) with `key`.
pub(super) fn usage(key: MessageKey, args: &[(&'static str, &str)]) -> Failure {
    Failure::message(Exit::Usage, key, args)
}
