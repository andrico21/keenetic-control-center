//! A listener's token sign-in that this process cannot enforce refuses the listener build.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    accounts::SystemClock,
    mcp_settings::ListenerKind,
    secrets::MasterKey,
    settings::{Config, mcp_schema::OauthMode},
};
use kcc_web::oauth::OAuthServer;

use super::{
    TestResult,
    fixture::{Fixture, Setup},
};
use crate::server_listeners::{build::BuildError, sign_in::tokens};

/// Todo 31 (S1), todo 33: `oauth = "external"` without a usable identity provider (the
/// fixture configures none) refuses the listener build with
/// [`BuildError::IdentityProvider`]; it is never silently ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_external_identity_provider_is_refused() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let mut settings = fixture.saved()?;
    settings.auth.main.oauth = OauthMode::External;
    let built = tokens(&fixture.shared, &settings, ListenerKind::Main);
    assert!(
        matches!(built, Err(BuildError::IdentityProvider(_))),
        "{built:?}"
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 31 (S1): with `[web] enabled = false` kcc's authorization server has no issuer,
/// so `oauth = "kcc"` refuses the listener build with
/// [`BuildError::SignInUnavailable`].
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcc_sign_in_without_the_web_ui_is_refused() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let disabled = Config::from_toml_str("[web]\nenabled = false\n")?;
    let server = OAuthServer::of(
        &disabled,
        (fixture.state.clone(), MasterKey::generate()?),
        Arc::new(SystemClock::default()),
    );
    assert!(server.is_none(), "no issuer without the Web UI");
    assert!(fixture.shared.sign_in.is_none(), "so serve has no sign-in");
    let mut settings = fixture.saved()?;
    settings.auth.main.oauth = OauthMode::Kcc;
    let built = tokens(&fixture.shared, &settings, ListenerKind::Main);
    assert!(
        matches!(
            built,
            Err(BuildError::SignInUnavailable { listener: "main" })
        ),
        "{built:?}"
    );
    fixture.stop().await??;
    Ok(())
}
