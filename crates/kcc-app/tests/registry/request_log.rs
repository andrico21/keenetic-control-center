//! Pages sharing a router's registry client share its collapsed warnings (todo 2).

extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use std::{
    io,
    sync::{Mutex, PoisonError},
};

use kcc_app::{
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    settings::OutboundConfig,
};
use kcc_rci::RciPath;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use tempfile::TempDir;
use tracing::{Level, subscriber::set_default};
use tracing_subscriber::fmt::MakeWriter;
use url::Url;

/// Everything the subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Two pages that each take the router's registry client and read the same failing
/// resource leave one warning, which names the router by its profile id.
#[tokio::test]
async fn two_pages_on_one_registry_client_warn_once() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let fake = FakeRouter::builder(Profile::default())
        .faults(FaultInjection::default().fail_read_matching("show/system", 2))
        .build()?;
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let registry = RouterRegistry::new(
        StateStore::open(&directory.path().join("state"))?,
        &[],
        &outbound,
    )?;
    let mut profile = ManagedRouterProfile::new(
        "lab-router".to_owned(),
        Url::parse(&format!("http://{address}"))?,
        "admin".to_owned(),
        password,
    );
    profile.label = Some("Lab Router".to_owned());
    registry
        .create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            profile,
        )
        .await?;
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(Level::TRACE)
        .with_writer(captured.clone())
        .finish();
    let guard = set_default(subscriber);
    let path = RciPath::from_segments(["show", "system"])?;

    let dashboard = registry.client("lab-router").await?.get(&path, &()).await;
    let system_page = registry.client("lab-router").await?.get(&path, &()).await;
    drop(guard);

    assert!(
        dashboard.is_err() && system_page.is_err(),
        "{dashboard:?} {system_page:?}"
    );
    let text = String::from_utf8_lossy(&captured.0.lock().unwrap_or_else(PoisonError::into_inner))
        .into_owned();
    let warnings = text
        .lines()
        .filter(|line| line.contains(" WARN ") && line.contains("path=/rci/show/system"))
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(
        warnings
            .iter()
            .all(|line| line.contains("router=lab-router") && line.contains("cause=http_500")),
        "{text}"
    );
    assert!(!text.contains("Lab Router"), "{text}");
    handle.shutdown().await?;
    Ok(())
}
