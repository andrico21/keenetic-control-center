//! The submit pipeline against a fake router.
//!
//! A value that fails its check is answered by the form and audited `validation_failed`,
//! and a change the domain could not plan is audited with its own reason. A planned
//! change that runs needs the request owner of the Web UI's middleware, so the page
//! suites cover it.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
pub(super) mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, net::SocketAddr, time::Duration};
    use std::path::{Path, PathBuf};

    use axum::{
        body::to_bytes,
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use kcc_app::{
        accounts::{AccountStore, Clock},
        audit::{AuditLog, verify_chain},
        backups::BackupStore,
        credentials::CredentialStore,
        permissions::built_in_roles,
        persist::StateStore,
        poller::Poller,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::{BackupsConfig, OutboundConfig},
        workflow::ChangeWorkflow,
    };
    use kcc_domain::{DomainError, wan};
    use kcc_i18n::{keys, locale::Locale};
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
    use tempfile::TempDir;
    use url::Url;

    use super::super::{Form, Invalid, Submission, rejected::Rejected};
    use crate::{
        WebState, WebStateConfig,
        authz::CurrentUser,
        fleet::{BackupServices, FleetServices},
        page_kit::{action::Operation, outcome::Failure, request::Params},
        session::CookieSecurity,
    };

    /// The MTU of a connection, the write the tests submit.
    pub(in crate::page_kit::submit) const MTU: Operation =
        Operation::write(&wan::DESCRIPTOR, "mtu", "web.wan_mtu");

    /// The profile id of the fake router.
    pub(in crate::page_kit::submit) const ROUTER: &str = "home";

    /// What the test form answers with, so the answer shows it came from the form.
    pub(in crate::page_kit::submit) const FORM_STATUS: StatusCode = StatusCode::IM_A_TEAPOT;

    /// Largest body a test reads.
    const BODY_CAP: usize = 0x0010_0000;

    /// A frozen clock.
    #[derive(Debug)]
    struct Frozen;

    impl Clock for Frozen {
        fn unix_seconds(&self) -> u64 {
            1_700_000_000
        }
    }

    /// A form that answers its findings with their field names.
    struct Probe;

    impl Form for Probe {
        fn answer_invalid(self, invalid: Invalid, _locale: Locale) -> Response {
            let fields: Vec<&str> = invalid
                .into_findings()
                .into_iter()
                .map(|(field, _rule)| field)
                .collect();
            (FORM_STATUS, fields.join(",")).into_response()
        }
    }

    /// The Web UI services over a fake router, its state directory and the router.
    pub(in crate::page_kit::submit) struct World {
        /// State and credentials.
        directory: TempDir,
        /// The services.
        web: WebState,
        /// The fake router.
        handle: Handle,
        /// The administrator.
        admin: CurrentUser,
        /// An operator, who may write but not take destructive risks.
        operator: CurrentUser,
    }

    impl World {
        /// A fresh state over a default fake router.
        // NOT cancel-safe: setup starts the router and the audit writer.
        pub(in crate::page_kit::submit) async fn new() -> Result<Self, Box<dyn Error>> {
            let directory = TempDir::new()?;
            let store = StateStore::open(&directory.path().join("state"))?;
            let clock: Arc<dyn Clock> = Arc::new(Frozen);
            let accounts = AccountStore::new(
                store.clone(),
                MasterKey::generate()?,
                Duration::from_secs(60),
                Arc::clone(&clock),
            );
            let password = kcc_testkit::write_secret_file(
                directory.path(),
                "router-password",
                DEFAULT_PASSWORD,
            )?;
            let mut outbound = OutboundConfig::default();
            outbound.allow_loopback = true;
            let registry = Arc::new(RouterRegistry::new(store.clone(), &[], &outbound)?);
            let (address, handle) = FakeRouter::builder(Profile::default())
                .build()?
                .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await?;
            let [_, operator, admin] = built_in_roles();
            registry
                .create(
                    &admin,
                    ManagedRouterProfile::new(
                        ROUTER.to_owned(),
                        Url::parse(&format!("http://{address}"))?,
                        DEFAULT_LOGIN.to_owned(),
                        password,
                    ),
                )
                .await?;
            let audit = AuditLog::spawn(&store)?;
            let backups = Arc::new(BackupStore::new(
                store.clone(),
                MasterKey::from_bytes([7_u8; 32]),
            ));
            let workflow = ChangeWorkflow::new(
                store.clone(),
                Arc::clone(&registry),
                Arc::clone(&backups),
                audit.clone(),
            );
            let web = WebState::new(WebStateConfig {
                default_locale: Locale::En,
                accounts: Arc::new(accounts),
                audit,
                roles: Vec::from(built_in_roles()),
                session_idle: Duration::from_secs(60),
                session_absolute: Duration::from_secs(600),
                allowed_origins: Vec::new(),
                cookie_security: CookieSecurity::LoopbackHttp,
                clock,
            })
            .with_fleet(FleetServices {
                registry: Arc::clone(&registry),
                poller: Poller::new(Arc::clone(&registry)),
                workflow,
                credentials: Arc::new(CredentialStore::new(store, MasterKey::generate()?)),
                update_check: None,
                backups: Some(BackupServices::new(backups, BackupsConfig::default())),
            });
            Ok(Self {
                directory,
                web,
                handle,
                admin: CurrentUser::signed_in("ada".to_owned(), admin, Locale::En),
                operator: CurrentUser::signed_in("oscar".to_owned(), operator, Locale::En),
            })
        }

        /// The services.
        pub(in crate::page_kit::submit) const fn web(&self) -> &WebState {
            &self.web
        }

        /// The fake router.
        pub(in crate::page_kit::submit) const fn handle(&self) -> &Handle {
            &self.handle
        }

        /// The administrator.
        pub(in crate::page_kit::submit) const fn admin(&self) -> &CurrentUser {
            &self.admin
        }

        /// An operator, who may write but not take destructive risks.
        pub(in crate::page_kit::submit) const fn operator(&self) -> &CurrentUser {
            &self.operator
        }

        /// The state directory.
        pub(in crate::page_kit::submit) fn state_dir(&self) -> PathBuf {
            self.directory.path().join("state")
        }
    }

    /// The outcomes audited for the MTU write so far.
    pub(in crate::page_kit::submit) fn outcomes(
        state_dir: &Path,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(verify_chain(state_dir)?
            .into_iter()
            .filter(|entry| entry.action == "web.wan_mtu")
            .map(|entry| entry.outcome)
            .collect())
    }

    /// The submitted MTU of `ISP`.
    pub(in crate::page_kit::submit) fn params(mtu: &str) -> Params {
        Params::of(vec![
            ("name".to_owned(), "ISP".to_owned()),
            ("value".to_owned(), mtu.to_owned()),
        ])
    }

    /// The MTU typed, or the field and rule it broke.
    pub(in crate::page_kit::submit) fn checked(params: &Params) -> Result<i64, Invalid> {
        params
            .text("value")
            .parse::<i64>()
            .map_err(|_error| Invalid::at("value", keys::WEB_INTERNET_MTU_ERROR))
    }

    /// The answer's body as text.
    pub(in crate::page_kit::submit) async fn body(
        response: Response,
    ) -> Result<String, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    #[tokio::test]
    async fn a_value_that_fails_its_check_is_answered_by_the_form() -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let opened = MTU.open(&world.web, &world.admin, ROUTER).await.ok();
        let action = opened.ok_or("the write opens")?;
        let before = world.handle.request_count();
        let typed = params("big");
        let answer = Submission::new(action, &typed, Probe)
            .submit(
                checked,
                async |_mtu, _domain| Err(DomainError::InvalidResponse),
                async |_domain| None,
            )
            .await;
        assert_eq!(answer.status(), FORM_STATUS, "the form answers");
        assert_eq!(body(answer).await?, "value", "at its field");
        assert_eq!(world.handle.request_count(), before, "nothing sent");
        assert_eq!(outcomes(&world.state_dir())?, ["validation_failed"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_plan_the_domain_refuses_is_audited_with_its_reason() -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        for refusal in [DomainError::PermissionDenied, DomainError::InvalidResponse] {
            let opened = MTU.open(&world.web, &world.admin, ROUTER).await.ok();
            let action = opened.ok_or("the write opens")?;
            let typed = params("1400");
            let answer = Submission::new(action, &typed, Probe)
                .submit(
                    checked,
                    async move |_mtu, _domain| Err(refusal),
                    async |_domain| None,
                )
                .await;
            assert_ne!(answer.status(), FORM_STATUS, "the outcome region answers");
        }
        assert_eq!(outcomes(&world.state_dir())?, ["forbidden", "failed"]);
        Ok(())
    }

    #[tokio::test]
    async fn values_read_against_the_router_are_audited_by_why_they_stop()
    -> Result<(), Box<dyn Error>> {
        let world = World::new().await?;
        let typed = params("1400");
        let mut statuses = Vec::new();
        for rejected in [
            Rejected::Invalid(Invalid::at("value", keys::WEB_INTERNET_MTU_ERROR)),
            Rejected::Failed(Failure::new(String::new(), "gone")),
            Rejected::Missing,
        ] {
            let opened = MTU.open(&world.web, &world.admin, ROUTER).await.ok();
            let action = opened.ok_or("the write opens")?;
            let before = world.handle.request_count();
            let answer = Submission::new(action, &typed, Probe)
                .submit_reading(
                    async move |_typed, _domain| Err::<(), _>(rejected),
                    async |(), _domain| Err(DomainError::InvalidResponse),
                    async |_domain| None,
                )
                .await;
            assert_eq!(world.handle.request_count(), before, "nothing sent");
            statuses.push(answer.status());
        }
        let [invalid, failed, missing] = statuses.as_slice() else {
            return Err("three answers".into());
        };
        assert_eq!(*invalid, FORM_STATUS, "the form answers invalid values");
        assert_ne!(*failed, FORM_STATUS, "the outcome region answers");
        assert_eq!(*missing, StatusCode::NOT_FOUND, "nothing to change");
        assert_eq!(outcomes(&world.state_dir())?, ["validation_failed", "gone"]);
        Ok(())
    }
}
