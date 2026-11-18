//! Runs whose source carries a password hash made for the target's own realm.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the same-realm password contract"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, str::FromStr as _};

    use kcc_config::config_text::parse;
    use kcc_migrate::{
        apply::{Applier, ApplyError},
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps},
        presets::{
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetMode, plan},
        },
        rules::Disposition,
    };
    use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile, ndw2, time::MockClock};
    use secrecy::SecretString;
    use tokio::net::TcpListener;

    use crate::{
        login::tests::{Advancing, fresh, router, run},
        support::Fixture,
    };

    /// The realm the fake target and every source here share.
    const REALM: &str = "Keenetic Giga";

    /// A source made on a router of the target's realm: a bridge address and the `admin`
    /// hash of a password that differs from both the current and the typed one.
    fn source() -> String {
        let hash = ndw2::ha1("admin", REALM, &["source", "only", "pw"].join("-"));
        format!(
            "! $$$ Model: {REALM}\n! $$$ Version: 4.3.0\ninterface Bridge0\n ip address 198.51.100.1 255.255.255.0\n!\nuser admin\n password md5 {}\n!\n",
            hash.as_str()
        )
    }

    /// A router-mode target of `REALM` whose timers follow `time`.
    async fn target(time: &Arc<MockClock>) -> Result<Fixture, Box<dyn Error>> {
        let builder = FakeRouter::builder(Profile::default()).realm(REALM);
        let fake = router(builder, time)?;
        Fixture::signed_in(fake, ("admin", DEFAULT_PASSWORD)).await
    }

    /// Signs in to the fixture's router as `admin` with `password`.
    async fn signs_in(fixture: &Fixture, password: &str) -> Result<(), Box<dyn Error>> {
        let client = RciClient::connect_with(
            RouterUrl::from_str(fixture.url.as_str())?,
            Credentials::new("admin".to_owned(), SecretString::from(password.to_owned())),
            RciClientOptions::default()
                .with_outbound(OutboundPolicy::default().with_loopback(true)),
        )
        .await?;
        drop(client.detect().await?);
        Ok(())
    }

    /// A password typed for `admin` wins over the same-realm hash the source
    /// carries; the router gets it, the run completes, and the typed password signs in.
    #[tokio::test]
    async fn typed_password_replaces_a_same_realm_hash() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let fixture = target(&time).await?;
        let typed = fresh("admin");
        let mut choices = Choices::default().with_reconnect_url(fixture.url.as_str().to_owned());
        drop(
            choices
                .new_passwords
                .insert("admin".to_owned(), SecretString::from(typed.clone())),
        );

        let request = fixture.plan_text(source(), &choices).await?;
        let expected = format!("user admin password plain {typed}");
        assert!(
            request
                .plan
                .phases
                .management
                .iter()
                .any(|line| line.expose_command() == expected),
            "the typed password is what the router gets"
        );
        let mut applier = run(&fixture, request, (&time, "admin")).await?;

        assert_eq!(applier.report().failure, None);
        signs_in(&fixture, &typed).await?;
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// Without a typed password, a same-realm hash for kcc's own login is
    /// refused with `PasswordRequired` before anything is sent.
    #[tokio::test]
    async fn same_realm_login_hash_without_a_password_is_refused() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let fixture = target(&time).await?;
        let before = fixture.handle.running_config_text();
        let choices = Choices::default().with_reconnect_url(fixture.url.as_str().to_owned());
        let mut request = fixture.plan_text(source(), &choices).await?;
        request.options.clock = Arc::new(Advancing::new(Arc::clone(&time)));

        let (_id, done) = Applier::start(&fixture.runner, request).await?;

        let outcome = done.await?.map(|applier| applier.report().failure);
        assert_eq!(outcome, Err(ApplyError::PasswordRequired));
        assert_eq!(fixture.handle.running_config_text(), before);
        assert!(!fixture.handle.recovery_armed());
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A run the router already rolled back by itself has nothing left to
    /// roll back; asking for it sends nothing and is not a refusal.
    #[tokio::test]
    async fn rollback_after_the_router_restored_itself_sends_nothing() -> Result<(), Box<dyn Error>>
    {
        let time = Arc::new(MockClock::new());
        let fixture = target(&time).await?;
        let unavailable = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}", unavailable.local_addr()?);
        drop(unavailable);
        let text = format!(
            "! $$$ Model: {REALM}\n! $$$ Version: 4.3.0\ninterface Bridge0\n ip address 198.51.100.1 255.255.255.0\n!\n"
        );
        let mut request = fixture
            .plan_text(text, &Choices::default().with_reconnect_url(url))
            .await?;
        request.options.clock = Arc::new(Advancing::new(Arc::clone(&time)));
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        let mut applier = done.await??;
        assert_eq!(
            applier.report().failure,
            Some(ApplyError::RolledBackByRouter)
        );
        let before = fixture.handle.request_log().len();

        let rolled_back = applier.rollback().await;

        assert_eq!(rolled_back, Ok(()));
        assert_eq!(fixture.handle.request_log().len(), before);
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A preset password typed for a user wins over that user's same-realm
    /// hash, as in a migration.
    #[tokio::test]
    async fn preset_typed_password_replaces_a_same_realm_hash() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let fixture = target(&time).await?;
        let hash = ndw2::ha1("operator", REALM, &["source", "only", "pw"].join("-"));
        let source = parse(&format!(
            "user operator\n password md5 {}\n!\n",
            hash.as_str()
        ))?;
        let selection = SettingsGroupEngine::embedded()?.select(&source, &["router-users"])?;
        let preset = Preset::captured(
            CaptureRequest::new(
                "users".to_owned(),
                "Users".to_owned(),
                String::new(),
                vec!["router-users".to_owned()],
                PresetSource::new(
                    PresetSourceKind::Router,
                    None,
                    REALM.to_owned(),
                    "4.3.0".to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        );
        let typed = fresh("operator");
        let mut choices = Choices::default();
        drop(
            choices
                .new_passwords
                .insert("operator".to_owned(), SecretString::from(typed.clone())),
        );
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        let inventory = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?;

        let planned = plan(
            &preset,
            &inventory,
            PresetMode::Merge,
            &MigrationMaps::default(),
            &choices,
        )?;

        let item = planned.items.first().ok_or("missing password item")?;
        assert_eq!(item.disposition, Disposition::Remap);
        assert_eq!(
            item.expose_command(),
            Some(format!("user operator password plain {typed}").as_str())
        );
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
