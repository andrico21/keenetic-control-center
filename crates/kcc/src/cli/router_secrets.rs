//! `router add` and `router edit`.
//!
//! Every credential they take is read once, sealed under the master key and referenced
//! only through its sealed record.

use std::path::Path;

use kcc_app::{
    credentials::{CredentialError, CredentialKind, CredentialStore},
    permissions::Permission,
    registry::{
        ManagedRouterProfile, ProfileSource, RegistryError,
        sealed_edit::{SealedEdit, update_sealed},
    },
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
    routers::{parse_label, parse_url},
    secret::{password_env_set, read_secret},
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
        .authorize_audited(services, &[Permission::ManageRouters], &[&args.id])
        .await?;
    let url = parse_url(&args.url)?;
    let label = args.label.as_deref().map_or(Ok(None), parse_label)?;
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
    let mut kinds = vec![primary];
    if args.credentials.read_login.is_some() {
        kinds.push(CredentialKind::ReadPassword);
    }
    let secrets = read_secrets(ctx, &id, &kinds, &args.credentials)?;
    let store = services.credentials();
    let mut profile = ManagedRouterProfile::new(
        id.clone(),
        url,
        args.login,
        store.sealed_path(&id, CredentialKind::Password)?,
    );
    profile.label = label;
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
/// The new secrets are sealed only for a valid profile, and a failed update puts the
/// previous sealed records back.
///
/// # Errors
///
/// Returns the command's failure with its exit code; a refused change writes nothing.
// NOT cancel-safe: writes the profile and its sealed records.
pub(crate) async fn edit(ctx: &Ctx, services: &Services, args: EditArgs) -> Outcome {
    let role = ctx
        .authorize_audited(services, &[Permission::ManageRouters], &[&args.id])
        .await?;
    let entry = services.registry().get(&args.id)?;
    if !matches!(entry.source, ProfileSource::State) {
        return Err(RegistryError::ConfigDefined { id: args.id }.into());
    }
    let id = args.id.clone();
    let plan = router_edit::plan(&entry.profile, args)?;
    if plan.profile().url != entry.profile.url {
        outbound::check(services.registry(), &plan.profile().url).await?;
    }
    let secrets = read_secrets(ctx, &id, plan.given(), plan.inputs())?;
    let store = services.credentials();
    let (mut profile, removed, changed) = plan.into_parts();
    point(store, &mut profile, &secrets)?;
    let edit = SealedEdit::new(profile, &secrets);
    update_sealed(services.registry(), store, &role, edit).await?;
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

/// Reads the secret of every kind in `kinds`, each from its input file, else
/// `KCC_PASSWORD` or a prompt; `KCC_PASSWORD` may stand in for one of them only.
///
/// # Errors
///
/// Returns a usage failure (exit 2) when two secrets would both come from
/// `KCC_PASSWORD`, else the command's failure with its exit code.
fn read_secrets(
    ctx: &Ctx,
    id: &str,
    kinds: &[CredentialKind],
    inputs: &CredentialArgs,
) -> Outcome<Secrets> {
    let unfiled = kinds
        .iter()
        .filter(|kind| source(ctx, **kind, inputs).0.is_none())
        .count();
    if unfiled > 1 && password_env_set() {
        return Err(usage(keys::CLI_ROUTER_PASSWORD_ENV_SHARED, &[]));
    }
    kinds
        .iter()
        .map(|kind| {
            let (file, prompt) = source(ctx, *kind, inputs);
            let secret = read_secret(file, &ctx.out().tr(prompt, &[("router", id)]))?;
            Ok((*kind, secret))
        })
        .collect()
}

/// The input file option and the prompt of the secret of `kind`.
fn source<'args>(
    ctx: &'args Ctx,
    kind: CredentialKind,
    inputs: &'args CredentialArgs,
) -> (Option<&'args Path>, MessageKey) {
    match kind {
        CredentialKind::Token => (inputs.token_file.as_deref(), keys::CLI_PROMPT_ROUTER_TOKEN),
        CredentialKind::ReadPassword => (
            inputs.read_password_file.as_deref(),
            keys::CLI_PROMPT_ROUTER_READ_PASSWORD,
        ),
        CredentialKind::Password | _ => (
            ctx.globals().password_file(),
            keys::CLI_PROMPT_ROUTER_PASSWORD,
        ),
    }
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
