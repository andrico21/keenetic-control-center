//! Entware at `/ui/r/{router}/system/entware`: its status, settings and actions.
//!
//! The page shows whether the router can run Entware, its components and architecture,
//! its `opkg` settings and drives, and the settings changes, the removal and the guided
//! setup the role may use.
//!
//! The page needs `Read`. Chroot and the time zone are writes; DNS override is a
//! management change that runs inside the fail-safe timer; the startup script, the
//! removal and the setup are destructive and need the router name typed. A router that
//! cannot run Entware shows why and offers nothing.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    entware::{
        self,
        models::{
            ArchResolution, ComponentPresence, EligibleDrive, EntwareStatus, Possibility,
            TimezoneSetting,
        },
    },
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use super::{
    entware_change::{CHROOT, DNS_OVERRIDE, INITRC, REMOVE, TIMEZONE},
    entware_setup::SETUP,
    shared::Visit,
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{action::Operation, context::fragment_shell, gate::Controls, request::rendered},
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_entware.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why Entware could not be read.
    problem: Option<MessageKey>,
    /// The status, the settings and the actions.
    region: Option<Region>,
}

localized!(Page);

/// One eligible drive, as the setup offers it.
pub(crate) struct Drive {
    /// The `opkg disk` argument, such as `label:/`.
    arg: String,
    /// Its medium, filesystem and free space, localized.
    details: String,
}

impl Drive {
    /// `drive` described in `locale`.
    fn new(drive: EligibleDrive, locale: Locale) -> Self {
        let mut args = FluentArgs::new();
        args.set("what", drive.media_id);
        args.set("kind", drive.filesystem);
        let key = drive
            .free_bytes
            .map_or(keys::WEB_SYSTEM_ENTWARE_DRIVE_OPTION_PLAIN, |bytes| {
                args.set("value", format::bytes(locale, bytes));
                keys::WEB_SYSTEM_ENTWARE_DRIVE_OPTION
            });
        Self {
            details: tr(locale, key, Some(&args)),
            arg: drive.disk_arg,
        }
    }
}

/// The actions the role may use, each also offered by the router's catalog.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per action of the page, each decided on its own"
)]
pub(crate) struct Offered {
    /// Turning chroot on or off.
    chroot: bool,
    /// Setting the time zone.
    timezone: bool,
    /// Turning DNS override on or off.
    dns_override: bool,
    /// Setting the startup script.
    initrc: bool,
    /// Removing Entware.
    remove: bool,
    /// Setting Entware up.
    setup: bool,
}

/// The status, the settings and the actions; a change sends it again out of band.
#[derive(Template)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one setting or notice of the router, read on its own"
)]
#[template(path = "partials/system_entware_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Why the router cannot run Entware, localized; nothing is offered then.
    blocked: Option<String>,
    /// The state of the `opkg` component.
    opkg: MessageKey,
    /// The state of the `ext` component.
    ext: MessageKey,
    /// The architecture, localized.
    arch: String,
    /// `opkg disk`, when set.
    disk: Option<String>,
    /// `opkg initrc`, when set.
    initrc: Option<String>,
    /// `opkg timezone`, localized, when set.
    timezone: Option<String>,
    /// Whether chroot is on.
    chroot: bool,
    /// Whether DNS override is on.
    dns_override: bool,
    /// Whether the router's DNS filter uses the `opkg` engine.
    dns_filter: bool,
    /// The drives Entware can use.
    drives: Vec<Drive>,
    /// The media that can be prepared with an ext4 initialize.
    initializable: Vec<String>,
    /// Whether the setup asks for the MIPS installer.
    installers: bool,
    /// What the role may do.
    offered: Offered,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);
fragment!(Region);

/// The localized reason the router cannot run Entware, or `None` when it can.
fn blocked(possible: &Possibility, locale: Locale) -> Option<String> {
    match possible {
        Possibility::Possible => None,
        Possibility::UnsupportedArch(arch) => {
            let mut args = FluentArgs::new();
            args.set("name", arch.clone());
            Some(tr(locale, keys::WEB_SYSTEM_ENTWARE_NO_ARCH, Some(&args)))
        }
        Possibility::NoUsbOrStorage | _ => Some(tr(locale, keys::WEB_SYSTEM_ENTWARE_NO_USB, None)),
    }
}

/// The label of a component's state; on a router that cannot run Entware (`blocked`) no
/// label promises the setup.
const fn presence(component: ComponentPresence, blocked: bool) -> MessageKey {
    match (component, blocked) {
        (ComponentPresence::Installed, _) => keys::WEB_SYSTEM_ENTWARE_INSTALLED,
        (ComponentPresence::Available, false) => keys::WEB_SYSTEM_ENTWARE_AVAILABLE,
        (ComponentPresence::Available, true) => keys::WEB_SYSTEM_ENTWARE_NOT_INSTALLED,
        (ComponentPresence::Missing | _, _) => keys::WEB_SYSTEM_ENTWARE_MISSING,
    }
}

/// The architecture, localized; on a router that cannot run Entware (`blocked`) only the
/// name the router reports.
fn arch(resolution: &ArchResolution, blocked: bool, locale: Locale) -> String {
    match (resolution, blocked) {
        (ArchResolution::Aarch64, false) => tr(locale, keys::WEB_SYSTEM_ENTWARE_ARCH_AARCH64, None),
        (ArchResolution::MipsAmbiguous, false) => {
            tr(locale, keys::WEB_SYSTEM_ENTWARE_ARCH_MIPS, None)
        }
        (ArchResolution::Aarch64, true) => "aarch64".to_owned(),
        (ArchResolution::MipsAmbiguous, true) => "mips".to_owned(),
        (ArchResolution::Unknown(name), _) => name.clone(),
        _ => tr(locale, keys::WEB_KIT_NOT_REPORTED, None),
    }
}

/// The time zone setting, localized.
fn timezone(setting: &TimezoneSetting, locale: Locale) -> String {
    match setting {
        TimezoneSetting::Named(name) => name.clone(),
        TimezoneSetting::Auto | _ => tr(locale, keys::WEB_SYSTEM_ENTWARE_TIMEZONE_AUTO, None),
    }
}

/// Who looks at Entware on which router.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
}

impl<'call> Viewer<'call> {
    /// `user` looking at Entware on `router`.
    pub(crate) const fn new(user: &'call CurrentUser, router: &'call str) -> Self {
        Self { user, router }
    }

    /// What the role may do with Entware in the state `status`, on a router whose
    /// catalog is `catalog`.
    fn offered(&self, status: &EntwareStatus, catalog: &Catalog) -> Offered {
        if status.possible != Possibility::Possible {
            return Offered::default();
        }
        let controls = Controls::new(self.user.role(), self.router);
        let may = |operation: Operation| operation.offered(&controls, catalog);
        let installed = status.settings.disk.is_some();
        Offered {
            chroot: installed && may(CHROOT),
            timezone: installed && may(TIMEZONE),
            dns_override: installed && may(DNS_OVERRIDE),
            initrc: installed && may(INITRC),
            remove: installed && may(REMOVE),
            setup: !installed && may(SETUP),
        }
    }

    /// The region for `status`.
    fn region(&self, status: EntwareStatus, catalog: &Catalog) -> Region {
        let locale = self.user.locale();
        let offered = self.offered(&status, catalog);
        let settings = status.settings;
        let reason = blocked(&status.possible, locale);
        let stuck = reason.is_some();
        Region {
            shell: fragment_shell(locale),
            router: self.router.to_owned(),
            blocked: reason,
            opkg: presence(status.opkg_component, stuck),
            ext: presence(status.ext_component, stuck),
            arch: arch(&status.arch, stuck, locale),
            disk: settings.disk,
            initrc: settings.initrc,
            timezone: settings
                .timezone
                .as_ref()
                .map(|setting| timezone(setting, locale)),
            chroot: settings.chroot,
            dns_override: settings.dns_override,
            dns_filter: status.dns_filter_uses_opkg,
            drives: status
                .drives
                .into_iter()
                .map(|drive| Drive::new(drive, locale))
                .collect(),
            initializable: status.initializable,
            installers: status.arch == ArchResolution::MipsAmbiguous,
            offered,
            oob: false,
        }
    }

    /// The region read again through `domain` after a change, out of band.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn refreshed(&self, domain: &RouterCtx) -> Option<Rendered> {
        let status = entware::read_status(domain).await.ok()?;
        rendered(&Region {
            oob: true,
            ..self.region(status, &domain.catalog)
        })
    }
}

/// `GET /ui/r/{router}/system/entware`: the status, the settings and the actions the role
/// may use.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
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
        tabs: TabBar::new(router.clone(), Tab::Entware),
        router: router.clone(),
        problem: None,
        region: None,
    };
    match reading {
        Ok((_, domain)) => match entware::read_status(&domain).await {
            Ok(status) => {
                let viewer = Viewer::new(&user, &router);
                page.region = Some(viewer.region(status, &domain.catalog));
            }
            Err(error) => {
                tracing::warn!(%error, "Entware status could not be read");
                page.problem = Some(keys::WEB_SYSTEM_READ_FAILED);
            }
        },
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
