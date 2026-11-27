//! A capture directory loaded into memory and replayed through a fake router.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{error::Error, net::SocketAddr, str::FromStr as _};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use kcc_catalog::Catalog;
use kcc_domain::RouterCtx;
use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials,
    capabilities::RouterInfo,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder, FaultInjection, Handle,
    capture::{Request, items},
    model::{Firmware, Model, Profile},
    outbound::connect_manager,
};
use secrecy::SecretString;
use serde_json::{Map, Value};

/// Integration-test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The variable naming the capture directory (an absolute path: cargo runs integration
/// tests from the crate directory).
pub(crate) const CAPTURE_DIR: &str = "KCC_LIVE_CAPTURE_DIR";

/// One captured item as written: JSON, or text (`.txt`).
enum Body {
    /// A `.json` file.
    Json(Value),
    /// A `.txt` file.
    Text(String),
}

/// Every item of one capture directory that has a file.
pub(crate) struct Capture {
    /// Items by name.
    items: BTreeMap<String, Body>,
}

/// Prints this suite's tracing events in the test output (once per process).
fn init_logging() {
    drop(tracing_subscriber::fmt().with_test_writer().try_init());
}

/// The capture directory, or `None` after logging `live-skip:no-capture-dir`.
///
/// # Errors
///
/// A relative path.
pub(crate) fn directory() -> TestResult<Option<PathBuf>> {
    init_logging();
    let Some(raw) = env::var_os(CAPTURE_DIR) else {
        tracing::info!("live-skip:no-capture-dir");
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!("{CAPTURE_DIR} must be an absolute path").into());
    }
    Ok(Some(path))
}

impl Capture {
    /// Loads every item `manifest.json` lists with a file; skipped items stay absent.
    ///
    /// # Errors
    ///
    /// I/O errors, or a manifest or `.json` item that does not parse.
    pub(crate) fn load(directory: &Path) -> TestResult<Self> {
        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(directory.join("manifest.json"))?)?;
        let listed = manifest
            .get("items")
            .and_then(Value::as_array)
            .ok_or("manifest.json lists no items")?;
        let mut loaded = BTreeMap::new();
        for entry in listed {
            let (Some(name), Some(file)) = (
                entry.get("name").and_then(Value::as_str),
                entry.get("file").and_then(Value::as_str),
            ) else {
                continue;
            };
            let text = fs::read_to_string(directory.join(file))?;
            let body = if Path::new(file)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            {
                Body::Json(serde_json::from_str(&text)?)
            } else {
                Body::Text(text)
            };
            drop(loaded.insert(name.to_owned(), body));
        }
        Ok(Self { items: loaded })
    }

    /// The JSON item `name`, if captured as JSON.
    pub(crate) fn json(&self, name: &str) -> Option<&Value> {
        match self.items.get(name) {
            Some(Body::Json(value)) => Some(value),
            Some(Body::Text(_)) | None => None,
        }
    }

    /// A KN-1811 fake that answers kcc's reads with the captured bodies only.
    ///
    /// `show` items become `show` fixtures (a text answer is served as text), the
    /// `show rc` items one merged `show rc` tree, `running-config` the running
    /// configuration, and each continued item its continued exchange; the final answer
    /// of `components-list` also answers `show components list`, which kcc reads. The
    /// one-shot `show-log` item is not replayed: kcc's log read sends no `once`, which
    /// is the request of `show-log-stream`.
    fn builder(&self) -> TestResult<FakeRouterBuilder> {
        let mut builder =
            FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_1)?).replayed();
        let mut faults = FaultInjection::default();
        let mut rc = Value::Object(Map::new());
        for item in items() {
            let Some(body) = self.items.get(&item.name) else {
                continue;
            };
            match (&item.request, body) {
                (Request::Show(path), Body::Json(value)) => {
                    let below = path.strip_prefix("show/").unwrap_or(path);
                    builder = builder.show_fixture(below, value.clone());
                }
                (Request::Show(path), Body::Text(text)) => {
                    faults = faults.show_answers_text(*path, text.clone());
                }
                (Request::ShowRc(_), Body::Json(tree)) => merge(&mut rc, tree),
                (Request::RunningConfig, Body::Text(text)) => {
                    faults = faults.config_answers_text("running-config.txt", text.clone());
                }
                (Request::Continued(path, _, _), Body::Json(Value::Array(answers))) => {
                    builder = builder.continued_fixture(*path, answers.clone());
                    if *path == "components/list"
                        && let Some(last) = answers.last()
                    {
                        builder = builder.show_fixture("components/list", last.clone());
                    }
                }
                // kcc's reads under test replay no other item.
                _ => {}
            }
        }
        for (root, tree) in rc.as_object().into_iter().flatten() {
            builder = builder.rc_fixture(format!("/{root}"), tree.clone());
        }
        Ok(builder.faults(faults))
    }

    /// Serves the replaying fake and connects a domain context to it.
    ///
    /// The catalog comes from a plain KN-1811 5.1 fake, so router detection never depends
    /// on the captured shapes under test.
    ///
    /// # Errors
    ///
    /// Fixture, bind, connection or detection errors.
    pub(crate) async fn spawn(&self) -> TestResult<(RouterCtx, Handle)> {
        let catalog = catalog().await?;
        let fake = self.builder()?.build()?;
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let client = RciClient::connect_with(
            origin(address)?,
            credentials(),
            RciClientOptions::default().with_outbound(loopback()),
        )
        .await?;
        Ok((RouterCtx::new(Arc::new(client), catalog), handle))
    }
}

/// The catalog kcc selects for a plain KN-1811 5.1 fake.
async fn catalog() -> TestResult<Catalog> {
    let plain = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_1)?).build()?;
    let (address, handle) = plain.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let router = origin(address)?;
    let manager = connect_manager(router.clone(), credentials(), &loopback()).await?;
    let info = RouterInfo::detect(&manager, &router).await?;
    handle.shutdown().await?;
    Ok(Catalog::for_router(&info)?)
}

/// The fake's origin.
fn origin(address: SocketAddr) -> TestResult<RouterUrl> {
    Ok(RouterUrl::from_str(&format!("http://{address}"))?)
}

/// The fake's default account.
fn credentials() -> Credentials {
    Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    )
}

/// An outbound policy that admits the loopback fake.
fn loopback() -> OutboundPolicy {
    OutboundPolicy::default().with_loopback(true)
}

/// Deep-merges the object `from` into `into`.
fn merge(into: &mut Value, from: &Value) {
    let (Value::Object(target), Value::Object(source)) = (into, from) else {
        return;
    };
    for (key, value) in source {
        match target.get_mut(key) {
            Some(existing) if existing.is_object() && value.is_object() => merge(existing, value),
            Some(_) | None => drop(target.insert(key.clone(), value.clone())),
        }
    }
}
