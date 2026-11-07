//! The page shell: everything the base layout renders around the page content.
//!
//! A [`Shell`] carries the request's locale and theme, the navigation state, the fleet
//! switcher, the selected router's status and the unsaved-change count. Every handler
//! builds one per request and embeds it in its askama template, whose `t(...)` and
//! `t_count(...)` calls format messages in the shell's locale.

use core::fmt;

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::nav::Section;

/// Colour theme picked in the header and stored in the `kcc_theme` cookie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Theme {
    /// Follow the operating system through `prefers-color-scheme`.
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl Theme {
    /// Name of the cookie that stores an explicit theme; no cookie means [`Theme::System`].
    pub const COOKIE_NAME: &str = "kcc_theme";

    /// Every theme, in menu order.
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    /// Parses a cookie value: `light` or `dark`; anything else is [`Theme::System`].
    #[inline]
    #[must_use]
    pub fn from_cookie(value: &str) -> Self {
        match value {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        }
    }

    /// The cookie value, also the theme menu's `data-kcc-theme` attribute.
    #[inline]
    #[must_use]
    pub const fn value(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// The class on `<html>` that overrides `prefers-color-scheme`, if any.
    #[inline]
    #[must_use]
    pub const fn class(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Light => Some("theme-light"),
            Self::Dark => Some("theme-dark"),
        }
    }

    /// The `color-scheme` the page declares, so browser-drawn controls match.
    #[inline]
    #[must_use]
    pub const fn color_scheme(self) -> &'static str {
        match self {
            Self::System => "light dark",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// The theme menu label.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        match self {
            Self::System => keys::WEB_THEME_SYSTEM,
            Self::Light => keys::WEB_THEME_LIGHT,
            Self::Dark => keys::WEB_THEME_DARK,
        }
    }
}

/// Reachability of the selected router, shown as the header status pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RouterStatus {
    /// The last poll reached the router.
    Online,
    /// The last poll failed.
    Offline,
    /// No poll has completed yet.
    Unknown,
}

impl RouterStatus {
    /// The pill label.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        match self {
            Self::Online => keys::WEB_ROUTER_ONLINE,
            Self::Offline => keys::WEB_ROUTER_OFFLINE,
            Self::Unknown => keys::WEB_ROUTER_UNKNOWN,
        }
    }

    /// The pill's `data-status` value, which selects its colour.
    #[inline]
    #[must_use]
    pub const fn value(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }
}

/// One router in the header fleet switcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetEntry {
    /// Router profile id, the switcher's option value.
    id: String,
    /// Display name.
    name: String,
    /// Whether this router is the one the page shows.
    selected: bool,
}

impl FleetEntry {
    /// Creates an entry for the router profile `id` named `name`.
    #[inline]
    #[must_use]
    pub const fn new(id: String, name: String, selected: bool) -> Self {
        Self { id, name, selected }
    }

    /// Router profile id.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Display name.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Whether this router is the one the page shows.
    #[inline]
    #[must_use]
    pub const fn selected(&self) -> bool {
        self.selected
    }
}

/// One navigation link and whether it is the current page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavLink {
    /// The linked section.
    section: Section,
    /// Whether the page belongs to this section.
    current: bool,
}

impl NavLink {
    /// The section's URL.
    #[inline]
    #[must_use]
    pub const fn href(self) -> &'static str {
        self.section.href()
    }

    /// The link label.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        self.section.label()
    }

    /// Whether the page belongs to this section (`aria-current="page"`).
    #[inline]
    #[must_use]
    pub const fn current(self) -> bool {
        self.current
    }
}

/// The endonym message of every supported locale, in [`Locale::ALL`] order.
const LOCALE_LABELS: [(Locale, MessageKey); 6] = [
    (Locale::En, keys::WEB_LOCALE_EN),
    (Locale::Ru, keys::WEB_LOCALE_RU),
    (Locale::Uk, keys::WEB_LOCALE_UK),
    (Locale::De, keys::WEB_LOCALE_DE),
    (Locale::Be, keys::WEB_LOCALE_BE),
    (Locale::Kk, keys::WEB_LOCALE_KK),
];

/// One entry of the language menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocaleOption {
    /// BCP 47 tag, the `lang` and `data-kcc-locale` attribute.
    tag: &'static str,
    /// The language's own name.
    label: MessageKey,
    /// Whether the page renders in this language.
    current: bool,
}

impl LocaleOption {
    /// BCP 47 tag, the `lang` and `data-kcc-locale` attribute.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> &'static str {
        self.tag
    }

    /// The language's own name.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        self.label
    }

    /// Whether the page renders in this language.
    #[inline]
    #[must_use]
    pub const fn current(self) -> bool {
        self.current
    }
}

/// One entry of the theme menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeOption {
    /// The theme.
    theme: Theme,
    /// Whether the page renders with this theme.
    current: bool,
}

impl ThemeOption {
    /// The `data-kcc-theme` attribute.
    #[inline]
    #[must_use]
    pub const fn value(self) -> &'static str {
        self.theme.value()
    }

    /// The menu label.
    #[inline]
    #[must_use]
    pub const fn label(self) -> MessageKey {
        self.theme.label()
    }

    /// Whether the page renders with this theme.
    #[inline]
    #[must_use]
    pub const fn current(self) -> bool {
        self.current
    }
}

/// Everything the base layout renders around the page content.
#[derive(Clone)]
pub struct Shell {
    /// Locale of every message on the page.
    locale: Locale,
    /// Colour theme.
    theme: Theme,
    /// Per-session CSRF token rendered into `<meta name="csrf-token">`.
    csrf_token: Option<String>,
    /// Section the page belongs to; `None` for error pages.
    section: Option<Section>,
    /// Routers in the fleet switcher.
    fleet: Vec<FleetEntry>,
    /// Status of the selected router.
    router_status: Option<RouterStatus>,
    /// Changes made in the Web UI and not yet saved to the router.
    unsaved_changes: u32,
}

impl fmt::Debug for Shell {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shell")
            .field("locale", &self.locale)
            .field("theme", &self.theme)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_token| "[REDACTED]"),
            )
            .field("section", &self.section)
            .field("fleet", &self.fleet)
            .field("router_status", &self.router_status)
            .field("unsaved_changes", &self.unsaved_changes)
            .finish()
    }
}

impl Shell {
    /// A shell in `locale` and `theme` with no section, no fleet and no pending changes.
    #[inline]
    #[must_use]
    pub const fn new(locale: Locale, theme: Theme) -> Self {
        Self {
            locale,
            theme,
            csrf_token: None,
            section: None,
            fleet: Vec::new(),
            router_status: None,
            unsaved_changes: 0,
        }
    }

    /// Marks `section` as the current page in the navigation.
    #[inline]
    #[must_use]
    pub const fn with_section(mut self, section: Section) -> Self {
        self.section = Some(section);
        self
    }

    /// Renders `token` into `<meta name="csrf-token">` for the request scripts.
    #[inline]
    #[must_use]
    pub fn with_csrf_token(mut self, token: String) -> Self {
        self.csrf_token = Some(token);
        self
    }

    /// Fills the fleet switcher and the selected router's status pill.
    #[inline]
    #[must_use]
    pub fn with_fleet(mut self, fleet: Vec<FleetEntry>, status: Option<RouterStatus>) -> Self {
        self.fleet = fleet;
        self.router_status = status;
        self
    }

    /// Shows the unsaved-changes badge when `count` is not zero.
    #[inline]
    #[must_use]
    pub const fn with_unsaved_changes(mut self, count: u32) -> Self {
        self.unsaved_changes = count;
        self
    }

    /// Locale of every message on the page.
    #[inline]
    #[must_use]
    pub const fn locale(&self) -> Locale {
        self.locale
    }

    /// Colour theme.
    #[inline]
    #[must_use]
    pub const fn theme(&self) -> Theme {
        self.theme
    }

    /// The CSRF token, if the page has a session.
    #[inline]
    #[must_use]
    pub fn csrf_token(&self) -> Option<&str> {
        self.csrf_token.as_deref()
    }

    /// Section the page belongs to.
    #[inline]
    #[must_use]
    pub const fn section(&self) -> Option<Section> {
        self.section
    }

    /// Routers in the fleet switcher.
    #[inline]
    #[must_use]
    pub fn fleet(&self) -> &[FleetEntry] {
        &self.fleet
    }

    /// Status of the selected router.
    #[inline]
    #[must_use]
    pub const fn router_status(&self) -> Option<RouterStatus> {
        self.router_status
    }

    /// Changes not yet saved to the router.
    #[inline]
    #[must_use]
    pub const fn unsaved_changes(&self) -> u32 {
        self.unsaved_changes
    }

    /// Every navigation link, marking the current section.
    #[inline]
    #[must_use]
    pub fn nav(&self) -> [NavLink; 14] {
        Section::ALL.map(|section| NavLink {
            section,
            current: self.section == Some(section),
        })
    }

    /// Every language menu entry, marking the page's language.
    #[inline]
    #[must_use]
    pub fn locales(&self) -> [LocaleOption; 6] {
        LOCALE_LABELS.map(|(locale, label)| LocaleOption {
            tag: locale.tag(),
            label,
            current: locale == self.locale,
        })
    }

    /// Every theme menu entry, marking the page's theme.
    #[inline]
    #[must_use]
    pub fn themes(&self) -> [ThemeOption; 3] {
        Theme::ALL.map(|theme| ThemeOption {
            theme,
            current: theme == self.theme,
        })
    }

    /// The page language's own name, shown on the language menu button.
    #[inline]
    #[must_use]
    pub fn locale_label(&self) -> MessageKey {
        LOCALE_LABELS
            .into_iter()
            .find_map(|(locale, label)| (locale == self.locale).then_some(label))
            .unwrap_or(keys::WEB_LOCALE_EN)
    }
}

/// Message formatting for templates: `{{ t(key) }}` and `{{ t_count(key, n) }}` in a
/// template resolve to these methods on its struct.
pub(crate) trait Localize {
    /// The shell of the page being rendered.
    fn shell(&self) -> &Shell;

    /// Formats `key` in the page's locale.
    #[expect(
        clippy::min_ident_chars,
        reason = "templates call `t(...)`, the name the template lint contract uses"
    )]
    fn t(&self, key: MessageKey) -> String {
        tr(self.shell().locale, key, None)
    }

    /// Formats `key` with the Fluent variable `$count` in the page's locale.
    fn t_count(&self, key: MessageKey, count: u32) -> String {
        let mut args = FluentArgs::new();
        args.set("count", count);
        tr(self.shell().locale, key, Some(&args))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::{keys, locale::Locale};

    use super::{
        FleetEntry, LocaleOption, Localize, NavLink, RouterStatus, Shell, Theme, ThemeOption,
    };
    use crate::nav::Section;

    /// A template stand-in exposing the shell.
    struct Page(Shell);

    impl Localize for Page {
        fn shell(&self) -> &Shell {
            &self.0
        }
    }

    #[test]
    fn theme_cookie_values() {
        assert_eq!(Theme::from_cookie("dark"), Theme::Dark, "dark");
        assert_eq!(Theme::from_cookie("light"), Theme::Light, "light");
        for other in ["", "system", "DARK", "dark;"] {
            assert_eq!(Theme::from_cookie(other), Theme::System, "{other}");
        }
        for theme in Theme::ALL {
            assert_eq!(
                Theme::from_cookie(theme.value()),
                theme,
                "{}",
                theme.value()
            );
        }
        assert_eq!(Theme::System.class(), None, "system follows the OS");
        assert_eq!(Theme::Dark.class(), Some("theme-dark"), "override class");
    }

    #[test]
    fn navigation_marks_only_the_current_section() {
        let shell = Shell::new(Locale::En, Theme::System).with_section(Section::Vpn);
        let current: Vec<&str> = shell
            .nav()
            .into_iter()
            .filter(|link| link.current())
            .map(NavLink::href)
            .collect();
        assert_eq!(current, ["/ui/vpn"], "one current link");
        let none = Shell::new(Locale::En, Theme::System);
        assert!(
            none.nav().iter().all(|link| !link.current()),
            "error pages have no current section"
        );
    }

    #[test]
    fn menus_mark_the_page_language_and_theme() {
        let shell = Shell::new(Locale::Kk, Theme::Dark);
        let tags: Vec<&str> = shell.locales().iter().map(|option| option.tag()).collect();
        assert_eq!(tags, ["en", "ru", "uk", "de", "be", "kk"], "every locale");
        let current: Vec<&str> = shell
            .locales()
            .into_iter()
            .filter(|option| option.current())
            .map(LocaleOption::tag)
            .collect();
        assert_eq!(current, ["kk"], "page language");
        assert_eq!(shell.locale_label(), keys::WEB_LOCALE_KK, "button label");
        let themes: Vec<&str> = shell
            .themes()
            .into_iter()
            .filter(|option| option.current())
            .map(ThemeOption::value)
            .collect();
        assert_eq!(themes, ["dark"], "page theme");
    }

    #[test]
    fn templates_format_in_the_shell_locale() {
        let page = Page(Shell::new(Locale::De, Theme::System));
        assert_eq!(page.t(keys::WEB_THEME_DARK), "Dunkel", "German");
        assert_eq!(
            page.t_count(keys::WEB_UNSAVED_CHANGES, 2),
            "2 ungespeicherte \u{c4}nderungen",
            "German plural"
        );
        let english = Page(Shell::new(Locale::En, Theme::System));
        assert_eq!(
            english.t_count(keys::WEB_UNSAVED_CHANGES, 1),
            "1 unsaved change",
            "English singular"
        );
    }

    #[test]
    fn debug_output_redacts_the_csrf_token() {
        let shell = Shell::new(Locale::En, Theme::System)
            .with_csrf_token("s3cr3t-token".to_owned())
            .with_fleet(
                vec![FleetEntry::new("home".to_owned(), "Home".to_owned(), true)],
                Some(RouterStatus::Online),
            )
            .with_unsaved_changes(3);
        let debug = format!("{shell:?}");
        assert!(!debug.contains("s3cr3t-token"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert_eq!(shell.csrf_token(), Some("s3cr3t-token"), "template value");
        assert_eq!(shell.unsaved_changes(), 3, "badge count");
        assert_eq!(
            shell.fleet().first().map(FleetEntry::name),
            Some("Home"),
            "fleet"
        );
    }
}
