//! Runs that change the password of the router account kcc signs in with.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the login credential order"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, future::ready, pin::Pin, time::Duration};

    use kcc_app::audit::{Actor, ActorKind};
    use kcc_config::config_text::parse;
    use kcc_migrate::{
        apply::{Applier, ApplyError, ApplyRequest, Clock},
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps},
        presets::{
            apply::{PresetApplyRequest, request},
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetMode, plan},
        },
    };
    use kcc_testkit::{
        DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder, migration,
        model::Profile,
        ndw2,
        time::{Clock as _, MockClock},
    };
    use secrecy::SecretString;

    use crate::support::Fixture;

    /// Recovery waits advance the router's clock instead of sleeping.
    #[derive(Debug)]
    struct Advancing(Arc<MockClock>);

    impl Clock for Advancing {
        fn now(&self) -> Duration {
            self.0.now()
        }
        fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.0.advance(duration);
            Box::pin(ready(()))
        }
    }

    /// A run-time password distinct from every router's current one.
    fn fresh(user: &str) -> String {
        [user, "replacement", "pw"].join("-")
    }

    /// A fake router in router mode whose timers follow `time`.
    fn router(
        builder: FakeRouterBuilder,
        time: &Arc<MockClock>,
    ) -> Result<FakeRouter, Box<dyn Error>> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Ok(builder
            .clock(Arc::<MockClock>::clone(time))
            .build()?
            .with_migration(scenario))
    }

    /// Plans a cross-model source whose user hashes are replaced by fresh passwords.
    async fn cross_model(
        fixture: &Fixture,
        text: &str,
        users: &[&str],
    ) -> Result<ApplyRequest, Box<dyn Error>> {
        let mut choices = Choices::default().with_reconnect_url(fixture.url.as_str().to_owned());
        for user in users {
            drop(
                choices
                    .new_passwords
                    .insert((*user).to_owned(), SecretString::from(fresh(user))),
            );
        }
        let source = format!("! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\n{text}");
        fixture.plan_text(source, &choices).await
    }

    /// Starts `request` with the advancing clock and the login's new password.
    async fn run(
        fixture: &Fixture,
        mut request: ApplyRequest,
        (time, login): (&Arc<MockClock>, &str),
    ) -> Result<Applier, Box<dyn Error>> {
        request.options.clock = Arc::new(Advancing(Arc::clone(time)));
        request.options.management_password = Some(SecretString::from(fresh(login)));
        let (_id, done) = Applier::start(&fixture.runner, request).await?;
        Ok(done.await??)
    }

    /// Whether each management line, in run order, sets a user's password.
    fn management_order(request: &ApplyRequest) -> Vec<bool> {
        request
            .plan
            .phases
            .management
            .iter()
            .map(|line| line.expose_command().starts_with("user "))
            .collect()
    }

    /// G-03: the management address line runs before the login's password line, and its
    /// reconnect must still use the password the router has.
    #[tokio::test]
    async fn address_change_before_login_password_reconnects_with_old_password()
    -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let builder = FakeRouter::builder(Profile::default());
        let fixture =
            Fixture::signed_in(router(builder, &time)?, ("admin", DEFAULT_PASSWORD)).await?;
        let text = format!(
            "interface Bridge0\n ip address 198.51.100.1 255.255.255.0\n!\nuser admin\n password md5 {}\n!\n",
            "ab".repeat(16)
        );
        let request = cross_model(&fixture, &text, &["admin"]).await?;
        assert_eq!(management_order(&request), [false, true]);

        let mut applier = run(&fixture, request, (&time, "admin")).await?;

        assert_eq!(applier.report().failure, None);
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// G-03: another user's password line runs first; it ends every session, and the
    /// reconnect after it must still sign in as `kcc` with its current password.
    #[tokio::test]
    async fn other_user_before_login_keeps_current_password() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let current = ["kcc", "current", "pw"].join("-");
        let builder = FakeRouter::builder(Profile::default())
            .user("admin", DEFAULT_PASSWORD, ["cli", "http-proxy"])
            .user("kcc", current.as_str(), ["cli", "http-proxy"]);
        let fixture = Fixture::signed_in(router(builder, &time)?, ("kcc", &current)).await?;
        let text = format!(
            "user admin\n password md5 {}\n!\nuser kcc\n password md5 {}\n!\n",
            "ab".repeat(16),
            "cd".repeat(16)
        );
        let request = cross_model(&fixture, &text, &["admin", "kcc"]).await?;
        assert_eq!(management_order(&request), [true, true]);

        let mut applier = run(&fixture, request, (&time, "kcc")).await?;

        assert_eq!(applier.report().failure, None);
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// A `router-users` preset carrying `user admin`'s same-realm hash for `password`.
    fn users_preset(realm: &str, password: &str) -> Result<Preset, Box<dyn Error>> {
        let hash = ndw2::ha1("admin", realm, password);
        let source = parse(&format!("user admin\n password md5 {}\n!\n", hash.as_str()))?;
        let selection = SettingsGroupEngine::embedded()?.select(&source, &["router-users"])?;
        Ok(Preset::captured(
            CaptureRequest::new(
                "users".to_owned(),
                "Users".to_owned(),
                String::new(),
                vec!["router-users".to_owned()],
                PresetSource::new(
                    PresetSourceKind::Router,
                    None,
                    realm.to_owned(),
                    "4.3.0".to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        ))
    }

    /// Builds the protected request of `preset` merged onto the fixture's target.
    async fn preset_request(
        fixture: &Fixture,
        preset: Preset,
    ) -> Result<ApplyRequest, Box<dyn Error>> {
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        let inventory = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?;
        let reviewed = plan(
            &preset,
            &inventory,
            PresetMode::Merge,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        Ok(request(PresetApplyRequest::new(
            Arc::clone(&fixture.workflow),
            fixture.audit.clone(),
            Actor::new(ActorKind::Cli, "operator".to_owned()),
            fixture.role.clone(),
            "target".to_owned(),
            preset,
            reviewed,
            inventory,
        ))?)
    }

    /// G-04: a preset that changes the password of kcc's own login is refused before any
    /// write without the new password, and applies through the management phase with it.
    #[tokio::test]
    async fn login_password_preset_requires_management_password() -> Result<(), Box<dyn Error>> {
        let time = Arc::new(MockClock::new());
        let realm = "Keenetic Giga";
        let builder = FakeRouter::builder(Profile::default()).realm(realm);
        let fixture =
            Fixture::signed_in(router(builder, &time)?, ("admin", DEFAULT_PASSWORD)).await?;
        let before = fixture.handle.running_config_text();

        let mut refused = preset_request(&fixture, users_preset(realm, &fresh("admin"))?).await?;
        refused.options.clock = Arc::new(Advancing(Arc::clone(&time)));
        let (_id, done) = Applier::start(&fixture.runner, refused).await?;
        let outcome = done.await?.map(|applier| applier.report().failure);
        assert_eq!(outcome, Err(ApplyError::PasswordRequired));
        assert_eq!(fixture.handle.running_config_text(), before);

        let supplied = preset_request(&fixture, users_preset(realm, &fresh("admin"))?).await?;
        assert_eq!(management_order(&supplied), [true]);
        let mut applier = run(&fixture, supplied, (&time, "admin")).await?;

        assert_eq!(applier.report().failure, None);
        assert_eq!(
            fixture.registry.poll_info("target").await?.hw_id(),
            Some("KN-1811")
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
