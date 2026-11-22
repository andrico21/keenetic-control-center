//! Storage at `/ui/r/{router}/system/storage`: the mounted media and the USB devices,
//! with Eject and Prepare for Entware where the role may use them and the router's catalog
//! has the command.
//!
//! Both are destructive: they need `Destructive` and the router name typed into the kit's
//! confirmation. Prepare for Entware is offered for a medium the router can initialize
//! with ext4.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, storage};
use kcc_i18n::{bundle::MessageKey, format, keys, locale::Locale};
use serde_json::Value;

use super::{
    shared::Visit,
    storage_actions::INITIALIZE,
    storage_tables,
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize as _, Shell},
    page_kit::gate::Controls,
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
        view::TableView,
    },
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_storage.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the storage could not be read.
    problem: Option<MessageKey>,
    /// The media.
    media: Option<TableView>,
    /// The USB devices.
    usb: TableView,
}

localized!(Page);

/// One mounted medium.
#[derive(Debug, Clone)]
pub(super) struct Medium {
    /// Router media id, such as `Media0`.
    id: String,
    /// Volume label.
    label: Option<String>,
    /// Filesystem.
    filesystem: Option<String>,
    /// Size in bytes.
    size: Option<u64>,
    /// Free bytes.
    free: Option<u64>,
    /// Size, as people read it.
    size_text: Option<String>,
    /// Free space, as people read it.
    free_text: Option<String>,
    /// Whether the router can initialize it with ext4.
    initializable: bool,
}

impl Row for Medium {
    const COLUMNS: &'static [&'static str] = &["id", "label", "filesystem", "size", "free"];
    const DEFAULT: Sort = Sort::new("id", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        let number = |value: Option<u64>| {
            value.map_or(SortKey::Missing, |bytes| SortKey::Number(bytes.into()))
        };
        let text =
            |value: Option<&String>| value.map_or(SortKey::Missing, |found| SortKey::text(found));
        match column {
            "label" => text(self.label.as_ref()),
            "filesystem" => text(self.filesystem.as_ref()),
            "size" => number(self.size),
            "free" => number(self.free),
            _ => SortKey::text(&self.id),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [
            Some(&self.id),
            self.label.as_ref(),
            self.filesystem.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|field| field.to_lowercase().contains(needle))
    }
}

impl Medium {
    /// Router media id.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Volume label.
    pub(super) fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Filesystem.
    pub(super) fn filesystem(&self) -> Option<&str> {
        self.filesystem.as_deref()
    }

    /// Size, as people read it.
    pub(super) fn size_text(&self) -> Option<&str> {
        self.size_text.as_deref()
    }

    /// Free space, as people read it.
    pub(super) fn free_text(&self) -> Option<&str> {
        self.free_text.as_deref()
    }

    /// Whether the router can initialize it with ext4.
    pub(super) const fn initializable(&self) -> bool {
        self.initializable
    }
}

/// One USB device.
#[derive(Debug, Clone)]
pub(super) struct Device {
    /// Router USB id.
    id: String,
    /// Vendor and product.
    name: String,
    /// Whether it is connected.
    connected: bool,
}

impl Device {
    /// Router USB id.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Vendor and product.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Whether it is connected.
    pub(super) const fn connected(&self) -> bool {
        self.connected
    }
}

/// The media and USB devices of the router of `domain`.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with its media.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn read(
    domain: &RouterCtx,
    locale: Locale,
) -> Result<(Vec<Medium>, Vec<Device>), MessageKey> {
    let volumes = storage::read_media(domain).await.map_err(|error| {
        tracing::warn!(%error, "router media could not be read");
        keys::WEB_SYSTEM_READ_FAILED
    })?;
    let devices = storage::read_usb(domain).await.unwrap_or_default();
    let media = volumes
        .into_iter()
        .filter_map(|volume| {
            let initializable = volume
                .extra
                .get("initialize-supported")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("ext4")));
            Some(Medium {
                id: volume.id?,
                initializable,
                size_text: volume.size.map(|bytes| format::bytes(locale, bytes)),
                free_text: volume.free.map(|bytes| format::bytes(locale, bytes)),
                label: volume.label,
                filesystem: volume.filesystem,
                size: volume.size,
                free: volume.free,
            })
        })
        .collect();
    let usb = devices
        .into_iter()
        .filter_map(|device| {
            let name = [device.vendor, device.product]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            Some(Device {
                id: device.id?,
                name,
                connected: device.connected.unwrap_or(false),
            })
        })
        .collect();
    Ok((media, usb))
}

/// `GET /ui/r/{router}/system/storage`: the media, the USB devices and the maintenance
/// actions the role may run.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<TableQuery>,
) -> Response {
    let (shell, reading) = match Visit::new(&headers, &current, &user)
        .open(&state, &router)
        .await
    {
        Ok(opened) => opened,
        Err(refusal) => return refusal.into_response(),
    };
    let mut page = Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::Storage),
        router: router.clone(),
        problem: None,
        media: None,
        usb: storage_tables::usb(&[], user.locale()),
    };
    match reading {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(storage::DESCRIPTOR.write_ops, Some(facts.catalog()));
            let allowed = (
                controls.allows("eject"),
                INITIALIZE.offered(&controls, facts.catalog()),
            );
            match read(&domain, user.locale()).await {
                Ok((media, usb)) => {
                    let base = format!("/ui/r/{router}/system/storage");
                    let table = Table::new(media, &query, base);
                    let viewer = (router.as_str(), user.locale());
                    page.media = Some(storage_tables::media(&table, allowed, viewer));
                    page.usb = storage_tables::usb(&usb, user.locale());
                }
                Err(message) => page.problem = Some(message),
            }
        }
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
