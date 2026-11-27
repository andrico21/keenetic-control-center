//! Starts a notifier over a fake router and a fake Telegram, and drives them.

extern crate alloc;

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};

use kcc_app::{
    accounts::{AccountStore, Clock, SystemClock},
    audit::{Actor, ActorKind, AuditEvent, AuditLog},
    jobs::JobRunner,
    notify_store::{
        NotifyEvent, NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats},
        token::NotifySecrets,
    },
    permissions::{Permission, Role},
    persist::StateStore,
    poller::{PollIntervals, Poller},
    registry::{ManagedRouterProfile, RouterRegistry},
    schedules::time::ZoneName,
    secrets::MasterKey,
    settings::{OutboundConfig, notifications::TelegramConfig},
};
use kcc_i18n::locale::Locale;
use kcc_telemetry::notify::delivery::Timings;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, fake_telegram::FakeTelegram, model::Profile};
use kcc_web::fleet_updates::ComponentsUpdateCheck;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;

use super::{
    super::{Deps, NotifyHandle, Options},
    ROUTER, Rig, TestResult, VISITOR_IP, VISITOR_MAC, VISITOR_NAME, WAIT,
};

/// A fake router with the default fixtures.
pub(super) fn fake() -> TestResult<FakeRouter> {
    Ok(FakeRouter::builder(Profile::default()).build()?)
}

/// A fake router whose hotspot lists only the unregistered visitor.
pub(super) fn fake_with_visitor() -> TestResult<FakeRouter> {
    Ok(FakeRouter::builder(Profile::default())
        .show_fixture(
            "ip/hotspot",
            json!([{"mac": VISITOR_MAC, "ip": VISITOR_IP, "name": VISITOR_NAME, "registered": false, "link": "up"}]),
        )
        .build()?)
}

/// Settings that send `events` to one chat.
fn settings(events: &[NotifyEvent]) -> TestResult<NotifySettings> {
    let mut settings = NotifySettings::default();
    settings.enabled = true;
    settings.events = events.iter().copied().collect();
    settings.chats = Chats::new(vec![Chat::new(
        ChatId::parse("4242")?,
        ChatLabel::parse("ops")?,
    )])?;
    Ok(settings)
}

/// Delivery timings short enough for a test.
fn timings() -> Timings {
    let mut timings = Timings::default();
    timings.merge_window = Duration::from_millis(20);
    timings.rate_spacing = Duration::from_millis(1);
    timings.backoff_base = Duration::from_millis(10);
    timings.backoff_cap = Duration::from_millis(100);
    timings
}

impl Rig {
    /// Starts the notifier with `events` selected over `first`, polled every 50 ms and
    /// retried every 100 ms after a failure.
    pub(super) async fn start(events: &[NotifyEvent], first: FakeRouter) -> TestResult<Self> {
        Self::start_labelled(events, first, None).await
    }

    /// As [`Rig::start`], the router's profile carrying the display name `label`.
    pub(super) async fn start_labelled(
        events: &[NotifyEvent],
        first: FakeRouter,
        label: Option<&str>,
    ) -> TestResult<Self> {
        let telegram = FakeTelegram::spawn().await?;
        let token = format!(
            "{}:{}",
            4242_u32,
            ["in", "process", "notify", "token", "value", "abcdefgh"].join("_")
        );
        telegram.expect_token(&token);
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let key = MasterKey::from_bytes([7_u8; 32]);
        state.write(&settings(events)?)?;
        NotifySecrets::set_token(&state, &key, &SecretString::from(token))?;
        let (address, router) = first.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let password =
            kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let mut profile = ManagedRouterProfile::new(
            ROUTER.to_owned(),
            Url::parse(&format!("http://{address}"))?,
            "admin".to_owned(),
            password,
        );
        profile.label = label.map(str::to_owned);
        registry
            .create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                profile,
            )
            .await?;
        let poller = Poller::with_intervals(
            Arc::clone(&registry),
            PollIntervals::new(
                Duration::from_millis(50),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_secs(60),
            ),
        );
        let audit = AuditLog::spawn(&state)?;
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone()).await?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let accounts = Arc::new(AccountStore::new(
            state.clone(),
            key.duplicate(),
            Duration::from_mins(15),
            Arc::clone(&clock),
        ));
        let updates = Arc::new(ComponentsUpdateCheck::new(
            Arc::clone(&registry),
            Arc::clone(&poller),
            Arc::clone(&clock),
        ));
        let mut telegram_config = TelegramConfig::default();
        telegram_config.api_url = Some(Url::parse(&telegram.url())?);
        let deps = Deps {
            state,
            key,
            registry,
            poller: Arc::clone(&poller),
            audit: audit.clone(),
            jobs,
            accounts,
            updates,
            clock,
            metrics: None,
        };
        let options = Options {
            telegram: telegram_config,
            default_locale: Locale::En,
            zone: ZoneName::parse("UTC")?,
            timings: timings(),
        };
        let notify = NotifyHandle::start(deps, options).await?;
        let results = poller.subscribe(ROUTER).await;
        Ok(Self {
            _directory: directory,
            telegram,
            address,
            router: Some(router),
            results,
            audit,
            notify,
        })
    }

    /// Waits until `count` more polls of the router `answered` (or failed).
    pub(super) async fn polls(&mut self, count: usize, answered: bool) -> TestResult {
        let mut seen = 0_usize;
        timeout(WAIT, async {
            while seen < count {
                if self.results.changed().await.is_err() {
                    break;
                }
                let matched = self
                    .results
                    .borrow_and_update()
                    .as_ref()
                    .is_some_and(|result| result.is_ok() == answered);
                if matched {
                    seen = seen.saturating_add(1);
                }
            }
        })
        .await?;
        if seen < count {
            return Err("the poller stopped".into());
        }
        Ok(())
    }

    /// Stops the fake router.
    pub(super) async fn stop_router(&mut self) -> TestResult {
        self.router
            .take()
            .ok_or("the router is not running")?
            .shutdown()
            .await?;
        Ok(())
    }

    /// Serves `next` on the router's address.
    pub(super) async fn serve_again(&mut self, next: FakeRouter) -> TestResult {
        let (_address, handle) = next.serve(self.address).await?;
        self.router = Some(handle);
        Ok(())
    }

    /// Waits until the fake Telegram received `count` messages.
    pub(super) async fn messages(&self, count: usize) -> TestResult {
        timeout(WAIT, self.telegram.wait_for_requests(count)).await?;
        Ok(())
    }

    /// The texts the fake Telegram received.
    pub(super) fn texts(&self) -> Vec<String> {
        self.telegram
            .requests()
            .iter()
            .map(|request| request.text().to_owned())
            .collect()
    }

    /// Appends an audit entry on the router as `alice` on the Web.
    pub(super) async fn audit(&self, (action, target): (&str, &str), outcome: &str) -> TestResult {
        let now = SystemClock::default().unix_seconds();
        drop(
            self.audit
                .append(
                    AuditEvent::new(
                        now,
                        Actor::new(ActorKind::Web, "alice".to_owned()),
                        action.to_owned(),
                    )
                    .with_router(ROUTER.to_owned())
                    .with_target(target.to_owned())
                    .with_params(Value::Null)
                    .with_result(outcome.to_owned(), format!("test-{action}")),
                )
                .await?,
        );
        Ok(())
    }
}
