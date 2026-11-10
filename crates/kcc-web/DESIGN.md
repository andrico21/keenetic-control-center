# kcc Web UI Design System

Source of truth for every colour, size, spacing value and component in `assets/css/app.css`.
A token a page needs and cannot find is added here first, then to the stylesheet.

## 0. Research Log

- Embedded refs: shortlisted `ibm.md` (Carbon), `hashicorp.md`, `vercel.md` -> picked
  `taste-skill.md` (Layer A, operational default; its own scope note sends dashboards and admin
  panels to Carbon/Fluent) + `ibm.md` (Layer B) because a router console is an enterprise
  operational tool: dense tables, forms, status, one accent. The official Carbon packages
  (React/SCSS) cannot be used in an askama + htmx app with a strict CSP and no build step, so
  this is a Carbon-*inspired* token set in one hand-written stylesheet, not Carbon itself.
- StyleGallery: `CATALOG.md` + `fixed-sidenav-shell` read; picked `sticky-aside` for the shell
  (see section 4).
- Lazyweb: skipped - todo 33 builds the shell and primitives only, no product screen yet.
  Todo 35 (first data pages): the Lazyweb and StyleGallery tooling was not available in this
  environment; the fleet grid and dashboard follow Carbon's dashboard conventions (tonal
  tiles, label/value lists, one data-visualization palette) on the existing tokens.
- Imagen drafts: skipped - no image-generation tool in this environment.

## 1. Atmosphere & Identity

A quiet control room for routers. Flat, rectangular, tonal: surfaces separate by a step of
grey, not by shadow. One blue marks the action and the current place; status speaks through
small tinted pills. Nothing decorates; every element reports state or offers an action.

Brief for the shell (every page): primary action is the page's own (the shell has none of its
own); priority 1 is the page title in `main`, 2 the selected router and its status, 3 the
navigation. Left out on purpose: logo art, icons, breadcrumbs, a footer, a user avatar (todo 34
adds the account menu), decorative badges. Required content: fleet switcher (or "no routers"
note), router status pill, unsaved-changes badge, language menu, theme menu, the 13 navigation
links, skip link, toast region, dialog container.

## 2. Color

Every token is `light-dark(light, dark)`; `color-scheme` on `:root` picks the column, so the
`theme-light` / `theme-dark` classes only change `color-scheme`.

| Role | Token | Light | Dark | Usage |
|---|---|---|---|---|
| Canvas | `--color-canvas` | #ffffff | #161616 | Page and `main` background |
| Chrome | `--color-chrome` | #f4f4f4 | #262626 | Masthead, side navigation, table heads |
| Raised | `--color-raised` | #ffffff | #393939 | Menus, dialog, toasts (with shadow) |
| Field | `--color-field` | #f4f4f4 | #262626 | Input and select fill; #ffffff / #393939 inside chrome |
| Hover | `--color-hover` | #e8e8e8 | #333333 | Hover on ghost controls and rows |
| Selected | `--color-selected` | #0f62fe 10% | #78a9ff 16% | Current navigation link wash |
| Selected ink | `--color-selected-ink` | #0043ce | #a6c8ff | Current navigation link text |
| Border | `--color-border` | #e0e0e0 | #393939 | 1px hairlines and table rules |
| Border strong | `--color-border-strong` | #8d8d8d | #8d8d8d | Field bottom edge (>= 3:1) |
| Text | `--color-text` | #161616 | #f4f4f4 | Body, headings |
| Text muted | `--color-text-muted` | #525252 | #c6c6c6 | Labels, notes |
| Placeholder | `--color-placeholder` | #6f6f6f | #a8a8a8 | Placeholder text (>= 4.5:1 on field) |
| Accent | `--color-accent` | #0f62fe | #0f62fe | Primary button fill |
| Accent hover | `--color-accent-hover` | #0050e6 | #0050e6 | Primary hover |
| Accent active | `--color-accent-active` | #002d9c | #002d9c | Primary pressed |
| On accent | `--color-on-accent` | #ffffff | #ffffff | Text on accent (5.0:1) |
| Secondary | `--color-secondary` | #393939 | #6f6f6f | Secondary button fill |
| Secondary hover | `--color-secondary-hover` | #4c4c4c | #5e5e5e | Secondary hover |
| Link | `--color-link` | #0f62fe | #78a9ff | Inline links |
| Focus | `--color-focus` | #0f62fe | #ffffff | Focus ring |
| Success | `--color-success-ink` / `-wash` | #0e6027 / #defbe6 | #6fdc8c / #42be65 16% | Online, success toasts |
| Danger | `--color-danger-ink` / `-wash` | #a2191f / #fff1f1 | #ff8389 / #fa4d56 16% | Offline, errors |
| Warning | `--color-warning-ink` / `-wash` | #684e00 / #fcf4d6 | #f1c21b / #f1c21b 16% | Unsaved changes |
| Info | `--color-info-ink` / `-wash` | #0043ce / #edf5ff | #78a9ff / #4589ff 16% | Info toasts |
| Toast tones | `--color-*-toast` | same opaque tone wash | success #2b3e30, danger #482c2e, warning #463f24, info #2b3649 | Floating toasts; always opaque so page content cannot bleed through |
| Neutral | `--color-neutral-ink` / `-wash` | #393939 / #e0e0e0 | #c6c6c6 / #393939 | Unknown status |
| Disabled | `--color-disabled` / `-ink` | #c6c6c6 / #8d8d8d | #525252 / #8d8d8d | Disabled controls (exempt) |
| Danger | `--color-danger` / `-hover` / `-active` | #da1e28 / #b81921 / #750e13 | same | Destructive button fill (white text 5.0:1) |
| Meter track | `--color-meter-track` | #e0e0e0 | #393939 | Gauge background |
| Meter fill | `--color-meter-fill` | #525252 | #c6c6c6 | Gauge value (5.9:1 / 6.8:1 on the track) |
| Chart download | `--color-chart-rx` | #0072c3 | #33b1ff | Traffic download line and swatch (4.6:1 / 6.4:1 on chrome) |
| Chart upload | `--color-chart-tx` | #ba4e00 | #ff832b | Traffic upload line (dashed) and swatch (4.6:1 / 6.2:1 on chrome) |
| Selection | `--color-selection` | #0f62fe 20% | #78a9ff 30% | `::selection` |
| Scrim | `--color-scrim` | #161616 50% | #000000 60% | Dialog and sheet backdrop |
| Shadow | `--color-shadow` | #000000 20% | #000000 60% | Floating surfaces only |

Measured contrast (WCAG 2.x): text 18.1 / 16.5, muted 7.8 / 10.6 (7.1 / 8.9 on chrome),
placeholder 4.6 / 6.4, link 5.0 / 7.7, on-accent 5.0, field edge 3.3 / 4.6. Toast
text on its opaque light/dark surfaces: success 7.00 / 6.70, danger 7.09 / 5.29, warning
7.11 / 6.25, info 7.09 / 5.16; every tone clears 4.5:1 for 14 px normal text. Warning
notice text on its wash: 7.11 light; dark, with the 16% wash over the surface under it,
7.59 on the canvas, 6.22 on chrome and 4.85 on a dialog's raised surface.

Rules: accent fills only the primary action; the current place uses the selected wash and ink;
status colour lives only in pills, badges, flags, notices, the banner, toasts and field errors.
Gauges stay neutral. The two chart colours are a blue/orange pair that stays distinct for the
common colour-vision deficiencies; upload is also dashed and both have text labels.

## 3. Typography

System fonts only (`font-src 'self'`, nothing vendored): `--font-sans` = system-ui stack with
Cyrillic coverage, `--font-mono` = ui-monospace stack for ids, addresses and code.

| Level | Token | Size | Weight | Line height | Tracking | Usage |
|---|---|---|---|---|---|---|
| H1 | `--text-h1` | 2rem | 400 | 2.5rem | 0 | Page title |
| H2 | `--text-h2` | 1.5625rem | 400 | 2rem | 0 | Section heading |
| H3 | `--text-h3` | 1.25rem | 600 | 1.75rem | 0 | Dialog and panel titles |
| Body | `--text-body` | 1rem | 400 | 1.5rem | 0 | Default text |
| Small | `--text-small` | 0.875rem | 400 / 600 | 1.25rem | 0.01em | Controls, nav, tables |
| Caption | `--text-caption` | 0.75rem | 400 | 1rem | 0.025em | Field labels, pills, errors |

Heading steps are 1.25x or more; small and caption differ from body by colour or weight too.

## 4. Spacing & Layout

Base unit 0.25rem (4px), Carbon spacing steps:

| Token | Value | Usage |
|---|---|---|
| `--space-1` | 0.125rem | Hairline offsets |
| `--space-2` | 0.25rem | Menu padding |
| `--space-3` | 0.5rem | Inside a group |
| `--space-4` | 0.75rem | Pill padding, cell padding |
| `--space-5` | 1rem | Control padding, masthead padding |
| `--space-6` | 1.5rem | Main padding (medium+) |
| `--space-7` | 2rem | Between groups, page top |
| `--space-8` | 2.5rem | Select arrow room |
| `--space-9` | 3rem | Menu offset under the masthead |

`--control-height` is 2.5rem (pointer) and 2.75rem under `pointer: coarse` (44 px targets).
`--sidenav-width` is 15rem. `--card-min` (19rem) and `--panel-min` (22rem) are the narrowest
fleet card and dashboard panel before the grid drops a column; `--chart-height` (14rem) is the
traffic chart's reserved height. Breakpoints: compact < 48rem, medium >= 48rem (masthead on one
row), wide >= 80rem (persistent side navigation).

Layout: app shell - persistent section navigation beside long admin pages -> sticky-aside
(https://github.com/changeroa/StyleGallery/blob/main/patterns/split-sidebar/sticky-aside.md);
scroll owner: the document (`html`); the navigation list sticks at the top of its column and
scrolls itself only when taller than the viewport; below 80rem the navigation is a popover
sheet opened by the Menu button; anti-patterns: a second scroll container for `main`,
`100vh` heights, a visual order different from DOM and focus order.

Layout (fleet overview `/ui/`): card grid - one tonal card per router in
`repeat(auto-fill, minmax(min(100%, --card-min), 1fr))`, so 390 px shows one column and
1440 px three or four; scroll owner: the document; anti-patterns: fixed card heights,
a scrolling grid box, cards nested in cards.

Layout (router dashboard `/ui/r/{router}`): stacked sections - header, notices, the live
region (banner + `repeat(auto-fit, minmax(min(100%, --panel-min), 1fr))` panels), then the
full-width traffic panel; scroll owner: the document; anti-patterns: a fixed-height
scrolling panel, the chart inside the live region (it would be re-created on every poll).

Layout (router form `/ui/routers/...`): single column, 40rem max, actions in one row that
wraps; scroll owner: the document.

Layout (admin pages `/ui/admin/*`, todo 44): stacked sections - tab bar, page head (title
and the primary action), then the table region (or the filter form above the audit table,
or the server panels); tables sit in `.table-wrap`, which scrolls sideways only for the
table itself; scroll owner: the document; anti-patterns: a fixed-height scrolling table,
tabs that hide pages the role may open, actions in a hover-only menu.
`--aside-width` (22rem) is the command explorer's search and group column; `--area-min`
(12rem) the RCI console body's minimum height.

Layout (command explorer `/ui/r/{router}/explorer`): list-detail - DOM and reading order
follow the brief's priorities (search and results, the command detail, the group tree);
from 64rem the search and the tree share a `minmax(16rem, --aside-width)` column (grid areas
`find`/`groups`) beside the detail, below that they stack in DOM order so a phone reaches the
selected command before the 58 groups; scroll owner: the document; nested scrollers: only
`.code` blocks and the arguments table (horizontal) and the native `<details>` of groups
and response pages; anti-patterns: a fixed-height scrolling result list, a sticky detail
column, rendering every catalog command up front (groups load their commands when opened,
50 per page).

Layout (RCI and CLI consoles `/ui/r/{router}/console/{rci,cli}`): single column, 60rem max,
method and path side by side from 48rem, then the body, the live check and the result;
scroll owner: the document; nested scrollers: `.code` blocks only.

Layout (advanced landing `/ui/advanced`): one table of routers with their tool links; scroll
owner: the document.

`--setting-label` (12rem) is the widest label column of a settings list. `--log-height`
(32rem) is the tallest the system log's line list grows before it scrolls itself.

Layout (system general `/ui/r/{router}/system/general`, the domain page kit's reference):
stacked sections - page head, router link, the system tab bar, the outcome region (hidden
while empty), the settings panels in the dashboard's
`repeat(auto-fit, minmax(min(100%, --panel-min), 1fr))` grid (identity, time), then the
restart and factory-reset panels in the same grid; scroll owner: the document;
anti-patterns: a success banner repeating its toast, settings rows whose height depends on
their button, an Edit button for a setting the page cannot change.

Layout (system pages `/ui/r/{router}/system/{users,services,components,storage,schedules,
keendns}`, todo 40): stacked sections - page head (title and the page's primary action),
router link, the system tab bar (wrapping onto more rows on a phone), the outcome region, then the page's region: a filter, a `.table-wrap` table and the pager (the
components page puts the firmware and queue panels first; KeenDNS shows panels only); the
page grid is `minmax(0, 1fr)` so a table never widens the page; scroll owner: the
document; nested scrollers: `.table-wrap` (horizontal, the table only); anti-patterns: a
fixed-height scrolling table, row actions in a hover-only menu, a control for an operation
the router's catalog lacks.

Layout (system log `/ui/r/{router}/system/logs`): stacked sections - page head with
Download, router link, tab bar, the filter, then the log view whose `.log-tail` (at most
`--log-height`, keyboard-focusable) scrolls the lines; scroll owner: the document; nested
scrollers: `.log-tail` (both directions, the log only); anti-patterns: polling the router
faster than every 5 s, a second `show log` stream when the collector runs.

Layout (system diagnostics `/ui/r/{router}/system/diagnostics`): stacked sections - page
head, router link, tab bar, the diagnostic form panel (tool choice, then only that tool's
fields in a `minmax(min(100%, 14rem), 1fr)` auto-fill grid), then the outcome region with
the job panel; scroll owner: the document; anti-patterns: one form per tool (four primary
buttons), output that only arrives at the end of the page.

`--lan-table-min` (60rem) is the narrowest a local network table gets before its
`.table-wrap` scrolls sideways; `--lan-field-min` (14rem) is the narrowest field of a dialog
field grid and of the clients filter.

Layout (local network pages `/ui/r/{router}/{clients,dhcp,segments}`, todo 36): stacked
sections - the family tabs (Clients, DHCP, Segments), page head (title and the view's primary
action), router link, the DHCP view switch, the outcome region, then the region
(`#clients-region`, `#dhcp-region`: filter, count, the table in `.table-wrap`, pager); scroll
owner: the document; nested scrollers: `.table-wrap` (the table, sideways) and the DHCP view
switch (sideways on a phone); anti-patterns: a fixed-height scrolling table, a row of seven
buttons per client, a filter that a sort or page link drops.

## 5. Components

Source anatomy: Carbon UI shell, button, text input, data table, tag, notification and modal,
restyled with these tokens; markup lives in `templates/base.html` and the macros of
`templates/components.html`.

### Masthead
- Structure: Menu button (compact/medium), brand link, context cluster (fleet switcher or
  "no routers" note, status pill, unsaved badge), preference menus.
- Spacing: padding `--space-3` / `--space-5`, gaps `--space-3` / `--space-5`.
- States: hover wash on ghost buttons; focus ring.
- Accessibility: the language button's name contains its visible text ("Language: English").
- Layout: grid areas; two rows below 48rem.

### Side navigation
- Structure: `<nav popover>` with a list of section links; `aria-current="page"` marks the page.
- States: hover wash, current = selected wash + selected ink + weight 600, focus ring inset.
- Accessibility: popover gives Escape and light dismiss; a Close button for touch.
- Layout: sticky column at wide, fixed sheet from the inline start below.

### Menu (language, theme)
- Structure: ghost button with `popovertarget`, `[popover]` list of buttons; the current
  entry has `aria-current="true"` and a CSS check glyph.
- States: hover wash, focus ring inset, current weight 600.
- Motion: none.

### Button
- Variants: primary (accent), secondary (grey), ghost (transparent, text ink).
- States: hover, active, focus-visible, disabled; one box in every state (min height
  `--control-height`, fixed padding, no state adds content).
- Radius: `--radius-control` (0).

### Field (`ui::field`)
- Structure: label above, input, error below with `aria-describedby` and `aria-invalid`.
- States: default, focus ring, invalid (2px danger outline inset), disabled.
- Fill `--color-field`, 1px bottom edge `--color-border-strong`.

### Sortable table (`ui::sort_header` + `table::Sort`)
- Structure: `<th scope="col" aria-sort>` holding a link that re-requests the page sorted;
  the handler sorts. Arrow glyph from CSS, hidden from assistive technology.
- Rules: 1px row rules, chrome-coloured head, tabular numerals.

### Status pill and badge
- Pill: caption text + 0.5rem dot in `currentColor` on a status wash; values online,
  offline, unknown. Badge: link with warning wash, pill radius.

### Dialog (`ui::dialog_body`)
- Structure: one `<dialog id="dialog">`; htmx loads content into `#dialog-content`, app.js
  calls `showModal()`; header with title (`#dialog-title`) and a `method="dialog"` Close form.
- Accessibility: native modal focus trap, Escape, focus return.

### Router card (`partials/router_card.html`)
- Structure: `<li class="router-card">` holding a title link to the dashboard, the status
  pill, an identity line (brand wordmark, model, hardware id), facts, CPU and memory gauges
  (only once a poll has reached the router), and a foot with the unsaved flag and Edit (or
  the `kcc.toml` note).
- Surface: chrome tone, no border, no shadow; groups separate by `--space-4`.
- Live: the fleet stream replaces the card's content (`sse-swap="router-<id>"`).

### Facts (`.facts`)
- `<dl>` of label/value rows; label muted, value end-aligned with tabular numerals.

### Gauge (`.gauge`)
- Label, value text, then a native `<meter>` (hidden from assistive technology because the
  text says the same). Track and fill are neutral tokens; no status colour.

### Panel (`.panel`)
- A dashboard group with an `h2` styled at the H3 size; same tone as the router card.

### Banner (`.banner`) and flag (`.flag`)
- Banner: warning wash block with text and actions (Save, Backups); a tonal block, never an
  edge stripe. Flag: a non-link pill (warning by default, `data-tone="info"`).

### Notice (`.notice`)
- Tones by wash: success (default), info, warning, error, neutral; `notice__title` for a bold
  first line. A `role="note"` notice is one paragraph (the tier notice with its link).
- Every tone other than the default has its own `.notice[data-tone]` rule: the kcc-web test
  `every_notice_tone_has_its_own_rule` fails for a `Tone` or a template's literal notice
  tone without one, which would otherwise render in the success colours.

### Traffic chart (`.traffic`)
- Legend `<dl>` with colour swatches and the newest rates as text, then the uPlot canvas
  (`role="img"` with a label). `app.js` feeds uPlot from the `traffic` events; the axis units
  are server-localized patterns in `data-units`, numbers and times use `Intl` with the page
  language. More than 45 s (three polls) without a sample breaks the lines instead of
  drawing a straight segment across time nobody watched. No animation.

### Choice and check (`.choice`, `.check`)
- Radio group in a `fieldset` with a legend; checkbox with its label and help text. The pin
  field shows only while "Pin one certificate" is selected (CSS `:has`).

### Danger buttons
- `button--danger`: filled, for the confirming button inside the dialog only.
  `button--danger-ghost`: danger ink on transparent, for the action that opens it.

### Toast (`ui::toast`)
- Structure: `#toasts` `role="status"` `aria-live="polite"` region; each toast has a message
  and a Close button; tone by wash (info, success, warning, error), never by an edge stripe.
- Surface: the tone-specific toast token is opaque in both themes. Dark tokens composite the
  16% tone wash over Raised so the tone remains visible without underlying text bleeding through.

### Page briefs (todo 35)

- Fleet overview. Primary action: open a router (card title link); "Add router" is primary
  only in the empty state, secondary otherwise, and shown only with ManageRouters.
  Priorities: 1 reachability, 2 health (internet, CPU, memory, clients), 3 unsaved flag.
  Left out on purpose: fleet totals and stat tiles, per-card timestamps, sparklines, icons.
  Required content: brand wordmark, name, model, hardware id, firmware, uptime, CPU and memory
  gauges, internet state, clients online, unsaved flag, reachability; Edit for state routers
  (ManageRouters), the `kcc.toml` note for config routers.
- Router dashboard. Primary action: Save, only while the router has unsaved changes and the
  role has Save. Priorities: 1 identity and reachability (with the support-tier notice),
  2 system health and internet/WAN, 3 Wi-Fi, clients, traffic. Left out on purpose: decorative
  icons, duplicate stat tiles, per-panel subtitles. Required content: name, status, brand,
  model, hardware id, serial, tier badge and notice with the FIRMWARE.md link, unsaved banner
  with Save and Backups, host name, firmware, update status, uptime, clients, CPU, memory,
  internet state, WAN table, radios, access points, traffic legend and chart.
- Router form. Primary action: Add router / Save changes. Secondary: Test connection,
  Cancel; Delete router in its own section (edit only). Required content: name (fixed when
  editing), address, login, password (write-only; empty keeps it when editing), sign-in
  note, certificate check (verify or pin + SHA-256), tags, test-device flag, test result.

### Admin tabs (`partials/admin_tabs.html`)
- Structure: `<nav class="tabs">` with one link per admin page the role may open (Users,
  Roles, API keys and Server need ManageUsers; Audit log needs ViewAudit);
  `aria-current="page"` marks the page.
- States: hover wash; current = selected wash + selected ink + weight 600, never an accent
  underline; focus ring inset. The list scrolls sideways at 320px instead of wrapping.

### Admin table region (`.admin-region`)
- Structure: the table and its pager in `#admin-region`; changes answer with the region
  out of band plus `#toasts` toasts, so the page never reloads.
- Row actions: ghost buttons in `.admin-actions` (forms are `display: contents`), each
  `aria-describedby` the row header; destructive ones are `button--danger-ghost` and open
  the typed-name confirmation dialog (`partials/kit_name_confirm.html`).
- State flags: the status pill (Active online, Disabled neutral) plus `.flag` pills for
  Locked (warning) and Password change pending (info); text always names the state.

### Pager (`partials/kit_pager.html`, `table::pager::Pager`)
- Previous and Next ghost links around "Page N of M"; shown only with more than one page
  of 50 rows; links keep the filter query.

### Copy field (`partials/admin_key_created.html`)
- A read-only monospace input holding the new API key, a secondary Copy button
  (`data-kcc-copy`, first-party handler) and a hidden `role="status"` confirmation; the
  dialog's Done closes it and the dialog empties its content, so the key leaves the DOM.

### Audit filter (`.audit-filter`)
- A GET form: actor, router, action, from and to dates in an auto-fill grid
  (12rem minimum per field), Apply (primary) and Clear (ghost); invalid dates show a
  field error and are ignored.

### Page briefs (todo 44)

- Users. Primary action: Add user. Priorities: 1 the accounts and their state, 2 roles,
  3 row actions. Left out on purpose: last sign-in tiles, avatars, bulk actions. Required
  content: username (with "you"), role, Active/Disabled, Locked, Password change pending,
  Change role, Disable/Enable, Unlock (only with counted failures), Delete; actions only on
  accounts below the signed-in role and never on the own account.
- Roles. Primary action: Add role. Priorities: 1 role and permissions, 2 router scope,
  3 how many accounts and keys hold it. Required content: built-in roles (read-only, with
  the Built-in flag), custom roles with Edit and Delete (Delete only when unused), the
  permission checkboxes (unheld ones disabled) and the scope field.
- API keys. Primary action: Create API key. Priorities: 1 name and role, 2 created and
  last used, 3 Revoke. Required content: the one-time key display with Copy and Done; the
  key is never shown again.
- Audit log. Primary action: Apply filters; Export JSONL is secondary. Priorities: 1 the
  hash-chain status, 2 the filters, 3 the entries newest first. Required content: time,
  actor and its front end, action, router, target, outcome, redacted parameters.
- Server. No primary action. Priorities: 1 version and uptime, 2 state directory health,
  3 configuration summary and command catalogs. Left out on purpose: secrets, credential
  paths, router logins.
### Command explorer and consoles (todo 42)

- Command list (`.command-list`, `.command-link`): rows separated by hairlines; the path in
  the mono face, the kind as a muted caption. A link opens the detail in place (htmx) and
  keeps the address bookmarkable (`?path=`).
- Group tree (`.tree`): native `<details>`; the commands of a group load when it opens, 50
  per page with Previous/Next.
- Command detail (`.command`): mono title, risk flag, facts list (kind, `no` form, interface
  type, since-version, CLI context, models in a `<details>`), manual links, arguments table,
  then the generated form: one input per argument, keyword selects, checkboxes for boolean
  keywords and the `no` form, secrets as empty password inputs, sub-commands as collapsed
  `<details>` fieldsets indented by depth.
- Code block (`.code`): chrome surface, mono small text, horizontal scroll for long lines,
  keyboard-focusable.
- Response viewer (`.viewer`): status messages first as flags by level (message info,
  warning, error), then the answer in pages of 200 lines, the first open and the rest
  collapsed; above 256 KiB the rest is a download.
- Outcome (`.outcome`): notice headline (success or error) with the validation problems,
  then the "router said" block (`.router-said`, chrome surface, mono messages) and the
  viewer; a success also sends a toast and the header's unsaved badge out of band.
- Job panel (`.job`): chrome surface with title, live status pill (`running`, `done`,
  `failed`) and Stop; the final answer replaces the waiting note.
- Confirmation (`ui::dialog_body`): writes confirm, management changes explain the fail-safe
  timer, destructive commands require the router name typed; the confirm button posts the
  original form again.

### Page briefs (todo 42)

- Command explorer. Primary action: Run (read) or Run command (change), only when the role
  holds the command's permission. Secondary: Preview request, Show how the router stores
  this. Priorities: 1 search, 2 the selected command and its form, 3 the group tree. Left out
  on purpose: command descriptions copied from the manual (the PDF link carries them),
  per-command icons, a recent-commands list. Required content: search box, results with
  kind, groups with counts and paging, path, kind, risk, background, `no` form, interface
  type, since-version, CLI context, models, manual page link, model manual link, arguments
  with types and keywords, the generated form, preview (method, endpoint, JSON, masked
  secrets, validation), stored lines, result viewer, job panel, console links (RawRci).
- RCI console. Primary action: Send. Secondary: Check. Required content: method, catalog
  path, JSON body (batch at the root), live validation result, result viewer.
- CLI console. Primary action: Run. Secondary: Check. Required content: CLI line, the
  matched catalog command with its explorer link, "send without validation" (administrators
  only), result viewer.

### Domain page kit (`src/page_kit/`)

The machinery every router page shares, so a domain page (todos 36-41, 43) is a route, a
view model, a form, a plan and one kit call. The explorer, the consoles, the router pages
and the admin pages run on it too. One module per responsibility:

| Module | Owns |
|---|---|
| `context` | `Caller::shell(state, section, router)`: the full-page shell with the fleet switcher (router selected); `target(state, user, router)`: the router of the route parameter (`is_profile_id`, then the role's visible profiles) or a `Refusal` (`page()`: 404, 403 or the logged 500; `status()` for fragments); `Target::context(state)`: the catalog facts and the `RouterCtx` to read and plan with; `managed()` (`ManageRouters`); `fragment_shell(locale)`. |
| `gate` | `command_permissions(risk)` for raw commands; `operation_permissions(permission, risk)` for curated ones (management and destructive also need `Destructive`: kcc arms the fail-safe timer); `Controls::new(role, router).with_operations(&DESCRIPTOR.write_ops, catalog)`: what templates use to hide controls (`allows("hostname")`); `allowed(user, router, permissions)`: the handler re-check before acting (403). |
| `family` | `Family::Commands` (explorer, consoles: every change asks, messages speak of commands) and `Family::Changes` (domain pages: management and destructive changes ask, messages speak of changes); `gate()` decides run or ask. |
| `confirm` | `Confirmation` (from the form), `Gate`, `Prompt` + `Resubmit`: the dialog in `#dialog-content` (`partials/kit_confirm.html`); confirming re-posts the original request (form values by `hx-include` from the page, so a secret never passes through the dialog); management explains the fail-safe timer, destructive needs the router name typed; decided on the server every time. |
| `typed_name` | `TypedNameForm` and `TypedNameDialog`: the typed-name delete of objects that are not routers (`partials/kit_name_confirm.html`). |
| `action` | The kit call: `Operation::write(&DESCRIPTOR, "hostname", "web.system_hostname").open(&state, &user, &router)` resolves the router (404), re-checks the operation's permissions (audited 403) and loads the catalog; the `Action` then gives `context()`, `confirm(risk, &confirmation, resubmit)`, `abandon(reason)`, `run(risk, Change)` and `run_with(risk, work)` for domain functions such as `system::reboot`; it audits how the action ended, once. |
| `change` | `Change::{Request, Batch, Cli, Delete}` through the leased `ChangeSet` (backup, conflict check, read-back, audit), the fail-safe timer armed around a management change; `Change::audit_params()`: catalog paths and field names only. |
| `outcome`, `failure` | `Outcome` (tone, headline, problems, router said, toasts, unsaved badge, status, audit id), `Toast`, `Failure`; `workflow_failure`, `rci_failure` and `plan_failure` map errors in the family's words, keeping only the router's message text and naming the field a read-back did not find (`VerificationFailed`). |
| `dialog` | `FieldDialog`: the one-field edit dialog (`partials/kit_field_dialog.html`); `show()` answers its `GET`, `invalid()` the field error as 422 in the dialog. |
| `secret`, `reveal` | `write_only(typed)`: an empty field keeps the stored secret; `is_secret`/`mask` for raw answers; `Reveal::new(state, user, router).show(name, read)`: the separate Reveal action (`RevealSecrets`, audited either way, the value only in its dialog, `partials/kit_reveal.html`). |
| `audit` | `Record`: one audit event per action (actor, router, target, outcome); parameters are field names (`field_names`), never values. |
| `facts` | `FactsCache` and `RouterFacts`: the router's catalog and safety mode, cached for 600 s, so validation never contacts the router. |
| `respond` | `Answer` (handlers return `Result<Response, Answer>` and use `?`), `open` (`HX-Redirect`), `retarget`, `in_dialog`, `close_dialog`, `unprocessable` (422), `region` (table and toasts out of band). |

Tables live beside the sort helper in the public `table` module: `table::rows::Table::new(rows,
&query, base)` filters (`?q=`, `Row::matches`), sorts (`Row::COLUMNS`, `Row::DEFAULT`,
`Row::key`) and pages (`table::pager::PAGE_ROWS` = 50) typed rows; its sort headers keep the
filter and its page links keep both.

Markup (`partials/kit_macros.html`): `outcome_region()` (`#page-outcome`, where actions
answer), `result(outcome)` (a failure stays in the region with the router's words; a success
says so in its toast and empties the region), `report`, `signals` (toasts and the unsaved
badge, out of band), `toasts`, `setting(id, label, value, dialog_url)` (one row of a settings
list), `secret_field(id, name, label, error, help)` (no value parameter) and
`filter(table, label)`; `partials/kit_pager.html` with a `pager` in scope.

Adding a domain page (`src/system_general.rs` is the reference):

1. Route function: `fn routes() -> Router<WebState>` in the page's module, merged in
   `web_router` with one `.merge(module::routes())` line; the page under
   `/ui/r/{router}/<section>/...` gets `Read` and the router scope from the route table.
2. View model: the page handler builds `Caller::new(&headers, &current, &user).shell(&state,
   Section::X, Some(&router))`, resolves `context::target`, reads the domain's typed models
   through `Target::context`, and passes `Controls::new(role, router).with_operations(...)`
   to the template, which shows a control only where `allows(name)`.
3. Form: a `FieldDialog` (or the page's own dialog) for `GET .../{field}`; parse the posted
   value at the boundary (`check`), a refusal re-renders the dialog with `invalid()`.
4. Plan: `let action = OPERATION.open(&state, &user, &router).await?;`, then the domain's
   planner on `action.context().await?` gives a `ChangeOp`, converted by its
   `change_request`; a `DomainError` becomes the field error (`plan_failure`).
5. Kit call: `action.confirm(op.risk, &confirmation, resubmit)` until confirmed, then
   `action.run(op.risk, Change::Request(request)).await` (or `run_with` for a domain function)
   and render the `Outcome` (`kit::result`), with the region read back out of band and the
   dialog closed (`respond::close_dialog`).

Tests per page (`tests/system_general.rs`): render per role, one successful write read back
with the unsaved badge, one validation failure that sends nothing, one router error with the
"router said" block, the destructive name check; the kit's own suite is `tests/page_kit.rs`.

### Settings list (`kit::setting`)
- `<dl class="settings">` inside a panel; one row per setting: label (muted), value (or
  "Not reported", muted), and a ghost Edit button opening the setting's dialog, described
  by its label, only where the role may change it. Rows are separated by 1px hairlines and
  are equally tall whether they hold a button or not; below 48rem the label sits above the
  value.

### Outcome region (`kit::outcome_region`)
- `#page-outcome`, `aria-live="polite"`, hidden while it holds nothing; actions target it.
  Failures stay there (notice, the router's words); successes only toast.

### Page brief (system general, the kit's reference page)

- System general (`/ui/r/{router}/system/general`). Primary action: none; each setting has
  its own Edit. Priorities: 1 identity (host name, description, domain name), 2 time (time
  zone, router clock, time synchronization), 3 restart and factory reset. Left out on
  purpose: uptime and firmware (the dashboard has them). Required content: the system tab
  bar, host name with Edit (`Write`), description with Edit (`Write`), domain name, time
  zone with Edit (`Write`), router clock, time synchronization or "Not reported" with Edit of
  the time server (`Write`), Restart router and Reset to factory settings (`Destructive`,
  router name typed), the outcome region.

### System pages (todo 40)

- Tab bar (`partials/system_tabs.html`, `system_pages::tabs::TabBar`): the admin tabs'
  anatomy (`.tabs`), one link per system page of the router, the current one marked with
  `aria-current="page"`; every system page and the general page show it under the router
  link. With nine tabs it wraps (`.tabs--wrap`) instead of scrolling sideways, so the
  current page's tab is always in view on a phone.
- Tag and day checkboxes (`.system-checks`): `.choice__option` checkboxes in an auto-fill
  grid of 10rem columns inside a `fieldset.choice` with its legend.
- Job panel (`partials/system_job.html`): the explorer's `.job` surface; the status pill
  follows `status` events, `.job-lines` (an ordered list, hidden while empty) gets one
  localized sentence per `line` event, `done` closes the event source; Stop (ghost) only for
  jobs that can stop halfway (diagnostics, not the component commit).
- Log view (`.log-view`, `.log-tail`, `.log-lines`): chrome surface, mono small lines that
  wrap; the stream's `tail` event replaces the list, `lines` events append to it.
- Diagnostic form (`.diagnostics-form`): a tool radio group, then the tool's fields; CSS
  `:has()` hides the other tools' fields (they are ignored by the server anyway).

### Page briefs (todo 40)

- Router users. Primary action: Add user (management, so only roles with `ManageUsers` and
  `Destructive`). Priorities: 1 the accounts, 2 their tags, 3 row actions. Left out on
  purpose: passwords (write-only, the secret-safe write is not merged yet), last-login
  facts. Required content: name with the "kcc signs in with it" flag, tags or "No tags",
  Edit tags and Delete (not on kcc's own login), the add dialog with name, the catalog's
  tags as checkboxes, the no-password note and the fail-safe note.
- Services. Primary action: none; each row has Turn on or Turn off. Priorities: 1 service
  name with the "Management access" flag, 2 state, 3 the switch. Required content: every
  catalog service, its state pill, switches only where the role may (management services
  also need `Destructive`).
- Components. Primary action: none. Priorities: 1 firmware version and Check for updates,
  2 the queued changes and Apply and restart, 3 the component table. Required content:
  firmware or "Not reported", the queue or its empty note, the commit text, the table with
  name, state (Installed, Available, To install, To remove) and Install/Remove, the commit
  job panel with its phases.
- Storage. Primary action: none. Priorities: 1 media (name, label, filesystem, size, free),
  2 their actions, 3 USB devices. Required content: Eject, Check and Format only where the
  catalog has them (Check and Format are hidden until a catalog does), the USB table.
- Schedules. Primary action: Add schedule. Priorities: 1 name, 2 description, 3 state and
  Add action. Required content: the one-word rule in the dialogs, action start or stop,
  time, days Monday to Sunday.
- KeenDNS. Primary action: none. Priorities: 1 the name and its state with Book or
  Release, 2 remote access, 3 web proxy entries. Left out on purpose: the current access
  level (the router does not report it; the text says so).
- Log. Primary action: none (Download is secondary). Priorities: 1 the latest lines, 2 the
  filter, 3 Download. Required content: the live note, the empty and no-match notes.
- Diagnostics. Primary action: Start. Priorities: 1 the tool, 2 its fields, 3 the job's
  live lines and Stop. Required content: ping (host, count), traceroute (host, maximum
  hops), ARP ping (address, interface, count), iperf3 (host, port, duration), the
  jobs-unavailable notice when no job runner is attached.

### Local network pages (todo 36)

- Family tabs (`partials/lan_tabs.html`): the admin tab markup and style for one router's
  Clients, DHCP and Segments pages; `/ui/clients` lists every router with the same links.
- Row action menu (`.lan-menu`): one ghost Actions button per row, described by the row
  header, opening a `[popover]` `.menu`; items open a dialog or post a one-button form; Remove
  is `.menu__item--danger`. `app.js` opens the menu above its button when it would leave the
  viewport.
- Client name cell: the name (or "Unnamed device", muted), then `.lan-flags`: the status pill
  (Online, or Offline in the neutral tone: a remembered device is not an error) and the info
  flag "Not registered". Blocked is an error-tone flag in the Access column.
- DHCP view switch (`.lan-views`): flat chrome links, the view shown in the selected wash and
  ink, never an underline.
- Field grid (`.lan-fields`): dialog fields in `repeat(auto-fit, minmax(--lan-field-min,
  1fr))`, each field starting at the top of its cell.
- Wizard (`partials/segments_*.html`): a step caption (`.lan-step`), the details, then the
  review as an ordered list (`.lan-steps`) with Back (ghost) and Create segment (primary);
  the server checks the details again at every step.

### Page briefs (todo 36)

- Clients. Primary action: none at page level; each row has its Actions menu. Priorities:
  1 who is there (name, online, registered), 2 where (MAC, IP, interface or access point,
  signal), 3 policy, access and schedule. Left out on purpose: traffic history and charts (no
  stored client telemetry), vendor icons, bulk actions, a separate state column. Required
  content: search, state and connection filters, count, name, online state, Not registered,
  MAC, IP, interface or access point, signal (or Wired), received and sent, policy, access
  (Blocked), schedule; Rename or Register, Block or Allow access, Set policy, Set schedule,
  Set priority, Wake up, Remove (registered devices only, confirmed).
- DHCP. Primary action: Add pool (pools view) or Add static lease (static leases view).
  Priorities: 1 the view's table, 2 the view switch, 3 row actions (Edit, Make static).
  Required content: pools (name, range, gateway, DNS, lease time, interface, state, Edit),
  static leases (device, MAC, address), active leases (device, MAC, address, interface,
  state, time left, Make static), ARP table (device, MAC, address, interface, state); the
  pool dialog and the static lease dialog with their field errors (outside every pool,
  address in use).
- Segments. Primary action: Create segment. Required content: the wizard (number, VLAN ID,
  router address, mask, DHCP range, switch ports, access point, connection policy; the
  review; Back, Create segment) and the note that listing and deleting arrive later.
### Network pages (todo 37)

Layout (network pages `/ui/r/{router}/{network,internet,wifi,mesh}`): stacked sections - the
network tab bar, page head (title; Add connection on the internet page), router link, the
outcome region (hidden while empty), then the region `#net-region` (a filtered table with its
pager, or the radio, access-point and device sections); tables sit in `.table-wrap`, which
scrolls sideways only for the table (`.net-table` is at least 40rem); scroll owner: the
document; nested scrollers: `.table-wrap` (horizontal) and the open dialog; anti-patterns: a
fixed-height scrolling table, actions only in a hover menu, an object name in a path segment.

Layout (interface drawer): side sheet - the shared `<dialog>` at the inline end, full height,
`min(36rem, 100vw)` wide (`.dialog:has(.drawer)`): Enable or Disable, the settings list, the
counters, the traffic chart; scroll owner: the dialog; anti-patterns: a second dialog over the
drawer (Edit replaces its content), a browser poll of the router (the chart listens to kcc).

- Network tab bar (`partials/net_tabs.html`): the admin tab styles; Interfaces, Internet,
  Wi-Fi, Mesh, the current page marked. The navigation marks Network for the first two and
  Wi-Fi for the others.
- Form dialog (`partials/net_form.html`, `net_form::FormDialog`): text, number and select
  inputs; each constraint (`required`, `maxlength`, `min`, `max`) carries its localized rule
  in `data-kcc-invalid`, which `app.js` gives to the browser's own check, so an invalid value
  is never sent; the server checks the same rule and answers 422 with the field error.
- Settings dialog (`partials/net_settings.html`): `kit::setting` rows whose Edit opens the
  setting's form dialog in place, then secondary switch buttons, each posting one change.
- Drawer (`partials/net_interface_detail.html`): Disable is `button--danger-ghost` (it can
  cut kcc off and asks first), Enable secondary; the counters are a `.facts` list; the
  traffic chart has the dashboard's anatomy and ids, `app.js` mounts it when htmx loads the
  drawer and stops listening once it leaves the page.
- Row tables: the row header holds the id in the mono face and the description as a muted
  caption line (`.net-table__note`); actions are ghost buttons in `.admin-actions`, each
  `aria-describedby` the row header; Delete and Restart are `button--danger-ghost`.

Page briefs (todo 37):

- Interfaces. Primary action: none; each row has its own. Priorities: 1 link and state,
  2 address and type, 3 security level. Left out on purpose: per-row counters (the drawer has
  them), bulk actions, icons. Required content: filter; sortable interface (with its
  description), type, link, state, address, security level; Details; Enable and Disable
  (Disable is a management change); the drawer's description and security level with Edit,
  type, link, state, address, MAC, MTU, default gateway, priority, counters, live traffic.
- Internet connections. Primary action: Add connection (`Write`). Priorities: 1 the internet
  state, 2 the connections in priority order, 3 the ping-check profiles. Left out on
  purpose: password entry (until the secret-write prerequisite lands the page shows only
  whether one is set), traffic (the dashboard has it). Required content: priority, name with
  description, type, state, address; Move up and down; Settings (type, address with Edit for
  IPoE, connect via, user name and password set or not, MTU, default route switch,
  priority); Delete with the name typed; ping-check profiles read-only.
- Wi-Fi. Primary action: none. Priorities: 1 access points, 2 radios, 3 devices. Left out on
  purpose: Wi-Fi password entry (presence only, same prerequisite), band steering (the router
  reports no state for it). Required content: radios (band, channel, width, power, country,
  Settings); access points (SSID, security, password set or not, hidden, state, schedule,
  segment, Settings, Enable or Disable, hide or show the name); devices (MAC, access point,
  SSID, signal, rates) with filter, sort and pages.
- Mesh. Primary action: none. Priorities: 1 members and status, 2 their actions. Required
  content: name, identifier, MAC, status; Check for updates and Update firmware (`Write`);
  Restart (`Destructive`, router name typed).
### DNS and VPN pages (todo 39, `src/dns_vpn/`)

Layout (DNS `/ui/r/{router}/dns[/filtering|records|lists|routes]` and VPN
`/ui/r/{router}/vpn[/servers]`, `/ui/r/{router}/vpn/peers/{tunnel}`): stacked sections - tab
bar, page head (title and the tab's actions, `#page-actions`), router link, the outcome
region, then the tab region (`#domain-region`: panels in the dashboard's auto-fit grid, then
one table in `.table-wrap` with its filter and pager); scroll owner: the document; nested
scrollers: `.table-wrap` (horizontal, tables keep a 36rem minimum) and the tab bar list;
anti-patterns: two tables on one tab (each tab has one filter and one pager), a fixed-height
scrolling table, a hover-only row action.

- Region (`partials/dns_vpn_region.html`, `region::Region`): a change answers with it out of
  band, together with `#page-actions`, so a new list or profile brings its action along.
- Row and panel actions (`partials/dns_vpn_macros.html`, `region::Act`): ghost buttons that
  open a dialog, post hidden fields (`.inline-form`, outcome in `#page-outcome`) or link;
  Delete is `button--danger-ghost` and asks for the object's name (kit typed-name dialog).
- Dialog form (`partials/dns_vpn_form.html`, `form::FormDialog`): label above, help and
  error below each input; selects and radio groups (`.choice`); inputs with `data-show`
  appear only while the `kind` radio holds one of their values (CSS `:has`); the upload form
  is `multipart/form-data` with a file input (`.field__file`).
- State in tables: the status pill (Enabled online, Disabled and Unknown neutral); secrets
  only as Set / Not set, never a value.

### Page briefs (todo 39)

- DNS servers. Primary action: Add server (protocol DNS over TLS, DNS over HTTPS or plain).
  Priorities: 1 the servers the router asks, 2 protocol, 3 options. Left out on purpose:
  latency tests, per-server statistics, Delete (the DNS domain has no removal yet).
  Required content: server, protocol, options, the empty state naming the provider's
  servers.
- Filtering. Primary action: Assign profile (only with a profile). Required content:
  filtering engine with Edit, DNS interception On/Off with its toggle, profiles with Add
  profile, assignments (host or interface, kind, profile).
- Static records, Domain lists, Routes by domain. Primary actions: Add record, Create list
  (rows: Add domain), Add route (only with a list). Required content: domain and address;
  list, description, included and excluded domains; list, interface, gateway.
- Connections. Primary action: Import WireGuard file; secondary: Add WireGuard connection.
  Priorities: 1 name and state, 2 type, 3 details. Required content: name, type, state pill,
  details (port and peer count, peer, network, protocol), Enable/Disable, Peers
  (WireGuard), Delete. The import outcome lists what the file had and kcc did not send
  (keys, address, DNS, ASC).
- Peers of a connection. Primary action: Add peer. Required content: Back to connections,
  the router's public key, listen port, private key Set/Not set, then per peer: public
  key, endpoint, allowed addresses, keepalive, preshared key Set/Not set, Edit.
- VPN servers. No primary action. Panels: PPTP/L2TP, SSTP, OpenConnect (state, Enable or
  Disable server, interface, client addresses with Edit, DNS servers with Edit),
  IPsec/IKEv2 (state, virtual IP, addresses, DNS servers, Edit), WireGuard server
  interfaces, and User access (router user tags, link to the router users page).

## 6. Motion & Interaction

No movement: state changes are instant. The one transition is the htmx request indicator's
opacity (150ms ease-out), off under `prefers-reduced-motion`. Async feedback follows htmx:
the indicator appears only for requests that run longer than its CSS delay (1s).

## 7. Depth & Surface

Strategy: tonal-shift, plus 1px hairlines between regions. Shadows only on floating surfaces:
`--shadow-raised` = `0 0.125rem 0.375rem var(--color-shadow)`.

| Token | Value | Usage |
|---|---|---|
| `--radius-control` | 0 | Buttons, fields, menus, dialog, toasts |
| `--radius-pill` | 62.5rem | Status pills and badges only |

## 8. Accessibility Constraints & Accepted Debt

WCAG 2.2 AA: contrast per section 2; visible focus everywhere, never covered; targets >= 24px
(44px on coarse pointers); full keyboard reach (popovers and dialog are native); reflow at
320px; `prefers-reduced-motion` respected.

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Theme and language menus do nothing without JavaScript | `base.html` | The Web UI requires htmx anyway; cookies are written client-side so no state-changing endpoint exists before CSRF (todo 34) | Todo 34 may add a POST fallback |
| The traffic chart is a canvas | `pages/dashboard.html` | uPlot draws on canvas; the chart has `role="img"` and a label, and the legend states the newest rates as text | A data table view if users ask for history values |
| Router forms need JavaScript | `pages/router_form.html` | Every state-changing request carries the CSRF header that `app.js` adds to htmx requests | Same as the menus |
| API key Copy needs the Clipboard API | `partials/admin_key_created.html` | Without it (or without JavaScript) the key stays selected in its read-only field for a manual copy | None needed |
| Explorer and console actions need JavaScript | `pages/explorer.html`, `pages/console_*.html` | Preview, Run, Check and Send are htmx posts carrying the CSRF header; search and the explorer's `?path=` page work without it | Same as the menus |
| Group tree loads on open | `pages/explorer.html` | A `<details>` opened without JavaScript stays empty; search still finds every command | Server-rendered group pages if asked |
| Domain page changes need JavaScript | `pages/system_general.html`, `partials/kit_*.html` | Edit dialogs, Restart and their confirmations are htmx requests carrying the CSRF header; the settings read without it | Same as the menus |
| Localized constraint messages need JavaScript | `partials/net_form.html` | Without `app.js` the browser shows its own message for a failed constraint; the server still refuses the value with the localized rule | None needed |
| The WireGuard import needs JavaScript | `partials/dns_vpn_form.html` | The upload is an htmx `multipart/form-data` post with the CSRF header; an upload over 64 KiB comes back as 413 with the dialog, which `app.js` swaps like a 422 | Same as the menus |
| System pages' live parts need JavaScript | `partials/system_job.html`, `pages/system_logs.html` | Job lines and new log lines arrive over server-sent events through the htmx SSE extension; without it the page shows the lines of its load and the job's panel only | Same as the menus |
| Diagnostic fields filter by `:has()` | `pages/system_diagnostics.html` | A browser without `:has()` shows every tool's fields; the server reads only the chosen tool's | None needed |

## Configuration and backups page (todo 41, `src/config_page/`)

Layout (configuration `/ui/r/{router}/config`): stacked sections - page head, router link,
the outcome region, the state panels (`#config-status`: Changes and Fail-safe timer in the
dashboard's `repeat(auto-fit, minmax(min(100%, --panel-min), 1fr))` grid), then the backups
section (`#config-backups`: head with Create backup and Upload from file, the retention
sentence, the filter, the table in `.table-wrap`, the pager, then the comparison form);
the page grid is `minmax(0, 1fr)` so the table never widens the page; scroll owner: the
document; nested scrollers: `.table-wrap` (horizontal, the table keeps a 36rem minimum)
and the open row menu; anti-patterns: a fixed-height scrolling table, a row of six buttons
per backup, a client-side diff.

Layout (comparison `/ui/r/{router}/config/diff`): stacked sections - page head, router and
page links, the outcome of the comparison (heading naming both sides, removed and added
counts, then the changed lines unified as one list or side by side in a two-column table),
then the comparison form to change the sides or the view; scroll owner: the document;
nested scrollers: the side-by-side table's `.table-wrap` (horizontal); anti-patterns:
unchanged lines between the changes, a secret value anywhere on the page.

- State panels (`partials/config_status.html`): Changes shows Saved (status pill, online
  tone) or Unsaved changes (warning flag), who changed it last, and Save while nothing is
  armed; Fail-safe timer shows Not armed (neutral pill) or Armed (warning flag) with the
  time left and Keep changes (the primary action then) and Roll back (danger ghost). Each
  state is text first; colour only repeats it.
- Backups table (`partials/config_backups.html`): the row header is the creation time
  (`<time data-kcc-time>`, localized by `app.js`, UTC text without JavaScript) with the age
  under it; Kind, Reason (a file name in the mono face), Size (end-aligned); the row ends
  with Download (with secrets for `RevealSecrets`, else without) and an Actions menu
  (`.menu.lan-menu.backups-menu`, the clients page's popover): Download without secrets,
  Compare with running, Restore with the wizard (once served), Raw restore and Delete
  (danger items, both ask for the router name).
- Comparison form (`partials/config_compare_form.html`): a GET form (From backup, To running
  configuration or backup, View one list or side by side), so it works without
  JavaScript and its result can be bookmarked.
- Changed lines (`.config-diff__line`, `.config-diff__cell`): mono small text that wraps; a
  removed line on the danger wash with a `-` glyph, an added one on the success wash with
  `+`, each with a visually hidden "Removed:" or "Added:"; side by side, removed lines sit
  left of the added lines of the same run, runs separated by a canvas gap.
- Confirmation (`partials/config_confirm.html`): the kit's destructive confirmation with
  this page's own words, the router name typed; confirming re-posts the action.
- Upload dialog (`partials/config_upload.html`): one file input (`.field__file`) with its
  1 MiB help; a refused file comes back in the dialog with the reason (not text, the line
  that does not parse, a checksum mismatch, no commands, a redacted copy, too large).

Page briefs (todo 41):

- Configuration and backups. Primary action: Save while the running configuration has
  unsaved changes and no fail-safe timer runs; Keep changes while it runs; none otherwise
  (Create backup is secondary). Priorities: 1 unsaved state and the fail-safe timer, 2 the
  backups and their actions, 3 comparing two configurations. Left out on purpose: backup
  contents on the page (only the comparison shows lines, redacted), stat tiles, a per-row
  restore preview. Required content: Saved or Unsaved changes, who changed last, Save
  (`Save`), Armed or Not armed with the time left, Keep changes (`Save`), Roll back
  (`Destructive`, router name typed), the retention set in `kcc.toml`, Create backup and
  Upload from file (`Write`), the filter, created time and age, kind, reason, size,
  Download (without secrets for everyone, with them for `RevealSecrets`), Compare with
  running, Restore with the wizard (`Migrate`; until the wizard is merged a note says it
  is not available), Raw restore (`Destructive` and `Migrate`), Delete (`Destructive`,
  router name typed), the comparison form.
- Comparison. Primary action: none (Compare is secondary). Priorities: 1 the changed
  lines, 2 what was compared and the counts, 3 the form. Required content: both sides
  named, lines removed and added, the unordered note past 1000 edits, the no-difference
  note.

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Configuration actions need JavaScript | `pages/config.html`, `partials/config_*.html` | Save, Keep changes, Roll back, Create, Upload, Delete and Raw restore are htmx requests carrying the CSRF header; the page, the downloads and the comparison work without it | Same as the menus |
| A raw restore answers after 25 seconds at most | `src/config_page/restore.rs` | The restore restarts the router and continues as its own task; the page says so and the audit log records how it ended | A job panel for raw restores if users ask |
## Migration wizard (todo 43, `src/migrate_wizard/`)

Layout (`/ui/migrate`): stacked sections - page head (title and Start migration), the
intro, the outcome region, the restore offer panel (only when the configuration page's
link asks for one), then "Your migrations" (a `.table-wrap` table); scroll owner: the
document; nested scrollers: `.table-wrap` (horizontal, the table only); anti-patterns: a
migration list that shows another account's migrations, a restore offer that skips the
reviewed plan.

Layout (`/ui/migrate/{id}`): stacked sections - page head (title), the "All migrations"
link, the step list, the source and target summary, the outcome region, the step panel
(`#wizard-step`, opened by a hairline), then Back while choices can still change; scroll
owner: the document; nested scrollers: `.table-wrap` (maps and review tables, horizontal)
and `.wizard-agreement__text` (an agreement's text, at most `--wizard-scroll`,
keyboard-focusable); anti-patterns: a fixed-height scrolling step panel, a step list that
hides where the user is, a live line list with its own scroll box (it grows with the
document), status colour outside pills, notices and warnings.

Tokens: `--wizard-mark` (1.5rem) is the step list's number box; `--wizard-scroll` (16rem)
the tallest an agreement's text grows before it scrolls itself; `--wizard-review-min`
(44rem) the narrowest the review table gets before its `.table-wrap` scrolls sideways.

- Step list (`.wizard-steps`): "Step N of 9" caption, then an ordered list of the nine
  steps, each a chrome box with a number box and its label. Done: the number box filled
  with the neutral wash; current: the selected wash and ink, weight 600, the number box
  outlined, `aria-current="step"`; to do: muted. Below 48rem the labels are visually
  hidden (kept for assistive technology; the caption and the step's `h2` name the
  current one), so the nine number boxes fit one row at 390px.
- Step panel (`#wizard-step`): one `h2` per step; a submit that fails answers the panel
  alone (422, swapped in place); a submit that moves on sends the browser to the
  migration's page (`HX-Redirect`), which shows the next step. Confirmed requests that
  fail answer into the panel and close the dialog.
- Source form (`.wizard-source`): kind radios, then only the chosen kind's field (router
  select, file input, backup select grouped by router), CSS `:has()`.
- Target report (`.wizard-report`): chrome surface with the facts (model, firmware,
  support tier, mode), the warnings (`.wizard-warning`, warning or error wash, text names
  the problem), the settings that stay (`<details>`), the agreements' texts, the tier
  acknowledgement checkbox and Continue; older target firmware shows the error and no way
  on.
- Map tables (`.wizard-map`): source object in the row header (mono), the router's object
  in a select (ports, radios by band) or a text field (interface names); a refused row
  keeps its value with `aria-invalid` and the field error.
- Review table: filter links (`.wizard-filters`, the selected wash for the current one,
  never an underline) with counts, then line, the setting (redacted, mono, the router's
  form after an arrow), the fate pill (`.wizard-fate`: success = migrated/applied,
  warning = differs/no answer, info = needs input, danger = refused, neutral = skipped,
  unsupported, left out) with its reason, and the choice (Migrate checkbox, or which
  value stays); choices save as they change; the kit pager.
- Inputs: write-only password fields per user (the kit secret field), component consent
  checkboxes with how many settings need each, the reconnect address field, each
  agreement's text with its acceptance checkbox.
- Preview: counts (`.facts`), the components installed first, the phases with their
  ordered commands (`.wizard-commands`: source line number, redacted command), the
  reconnect address, the downloads (plan JSON, report Markdown and HTML), Apply (asks in
  the dialog with the fail-safe minutes).
- Apply (`.job.wizard-run`): the job surface with Stop (ghost) while it runs (hidden once
  the end arrived, CSS `:has()`), the neutral
  progress bar and "N% sent", the heartbeat sentence (how long the router's fail-safe
  timer still runs, every 10 s), the sent lines (`.wizard-run__line`: line number, the
  redacted command, the outcome pill) appended as they arrive, then the end notice with
  Review the result. A reload replays every line from the start.
- Results: the result notice, the applied and refused counts, the countdown sentence
  while changes wait, then the buttons: Commit (primary, verified only), Review the plan
  again, Back to the preview, Roll back (`button--danger-ghost`, the router name typed in
  the dialog), Finish.
- Report: how it finished, when, the counts, the report downloads, All migrations.

### Page briefs (todo 43)

- Migrations. Primary action: Start migration (Start restore when the link offers one;
  Start migration is then secondary). Priorities: 1 the restore offer when present, 2
  start, 3 the user's migrations. Left out on purpose: other accounts' migrations,
  progress tiles. Required content: intro, the restore offer (backup name, router) or
  why it cannot be offered, the list (started, kind, source, target, step) or its empty
  note.
- Wizard, every step. Primary action: the step's own (Continue, Read the router, Preview
  the plan, Apply the migration, Review the result, Commit); Back is ghost. Priorities: 1
  the step's question or result, 2 its form or list, 3 where the migration is (step list,
  summary). Left out on purpose: a per-step subtitle beyond the one-line explanation,
  icons, a progress percentage across the wizard. Required content per step: (1) kind,
  router, file, backup; (2) target select, source firmware when needed, the target facts,
  warnings, settings that stay, agreements, the tier acknowledgement, the older-firmware
  refusal; (3) port, radio and interface maps; (4) filters with counts, every setting with
  line, redacted text, fate, reason and choice, pager; (5) passwords, components,
  reconnect address, agreements, the blocked settings; (6) counts, components, phases
  with commands, reconnect address, downloads, Apply or why not; (7) Stop, progress,
  heartbeat, sent lines with outcomes, the end with Review the result; (8) result,
  counts, countdown, Commit / Roll back / Review the plan again / Back to the preview /
  Finish; (9) how it finished, when, counts, downloads.

## Routing, port forwarding and firewall pages (todo 38, `src/routing_page/`, `src/nat_page/`, `src/firewall_page/`)

Layout (static routes `/ui/r/{router}/routing[/ipv6]`, routing table
`/ui/r/{router}/routing/table[/ipv6]`, connection policies `/ui/r/{router}/routing/policies`,
port forwarding `/ui/r/{router}/nat[/interfaces|/sessions]`, firewall interfaces and UPnP
`/ui/r/{router}/firewall/{interfaces|upnp}`): stacked sections - the family tabs (Static
routes, Routing table, Connection policies, Port forwarding, Firewall; they wrap on a
phone), page head (title and the view's primary action), router link, the view switch
(`.lan-views`: IPv4 and IPv6; Rules, NAT interfaces and Active connections; Access lists,
Interfaces and UPnP), the outcome region (hidden while empty), then the region
`#routing-region` (filter, one table in `.table-wrap`, pager); scroll owner: the document;
nested scrollers: `.table-wrap` (horizontal, the table keeps `--routing-table-min`), the view
switch (sideways on a phone) and an open row menu; anti-patterns: two sortable tables on one
view, a fixed-height scrolling table, a hover-only row action, an object name in a path
segment.

Layout (firewall access lists `/ui/r/{router}/firewall`): stacked sections - tabs, head (Add
rule), router link, view switch, outcome region, then one section per list
(`.firewall-list`: the list name with Add rule and Apply to interface, where the list applies
as info flags, then its rules in the router's order in a `.table-wrap` table), then the IPv6
section (the read-only IPv6 lists, or the note with the command explorer link); scroll owner:
the document; nested scrollers: each `.table-wrap` (horizontal); anti-patterns: sorting or
paging rules (their order is what the router checks), drag-and-drop ordering, an action on a
rule that does not name its position and stored words.

Tokens: `--routing-table-min` (40rem) is the narrowest a table of these pages gets before its
`.table-wrap` scrolls sideways; the active connections table keeps 56rem.

- Family tabs (`partials/routing_tabs.html`, `routing_page::frame::Tab`): the admin tab
  styles in the wrapping variant (`.tabs--wrap`); the navigation marks Routing for the first
  three and Firewall for port forwarding and the firewall.
- Route-wipe banner (`.routing-guard` in `partials/routing_result.html`): a `role="alert"`
  section in the outcome region, in place of the outcome's notice, after the router answered
  one route's removal by clearing every route. When every route it had before is back: the
  warning wash, "The router cleared every route. kcc put them back.", the count sentence
  ending "Nothing was lost:", the restored routes as stored commands in the mono face, and
  that the route asked for is still there. When some are missing: the danger wash and the
  missing routes. Tone by wash only, never an edge stripe; text says the state first.
- Removal confirmation (`partials/routing_confirm.html`): title naming the object, what the
  removal does, one danger button; the answer lands in the outcome region.
- Policy interfaces (`.routing-permits`): an ordered list in the policy's row, each interface
  with its order and a ghost Remove described by the policy and the interface.
- Rule actions (`.firewall-rules__actions`): Move up and Move down as ghost buttons (absent at
  the ends of the list), then the row's Actions menu (Enable or Disable, Description,
  Schedule, Remove in the danger tone); every control is described by the list and the rule's
  position.
- Active connections pager: Previous and Next by the router's pages of 200 and "Connections
  201 to 400"; the filter form keeps the page, and the note under it says that sorting and the
  filter apply to the page shown.

Page briefs (todo 38):

- Static routes. Primary action: Add route (`Write`). Priorities: 1 destination, 2 gateway and
  interface, 3 metric. Left out on purpose: learned routes (the routing table has them),
  per-route statistics, a bulk delete. Required content: the IPv4/IPv6 switch, filter,
  destination, gateway, interface, metric (IPv4), Remove (asks first; runs through the
  route-wipe guard, whose banner reports a router-wide clear), the add dialog (network and mask
  or prefix, gateway, interface, metric), the empty state pointing at the routing table.
- Routing table. Primary action: none. Priorities: 1 destination, 2 gateway and interface,
  3 metric and source. Required content: the IPv4/IPv6 switch, filter, sortable columns, the
  Static marker for configured routes.
- Connection policies. Primary action: Add policy (`Write`). Priorities: 1 name, 2 interfaces in
  order, 3 multipath and description. Required content: filter, name, description, the
  interfaces with their order and Remove, multipath state, the Actions menu (Description, Add
  interface with its order, Turn multipath on or off, Delete with the name typed).
- Port forwarding. Primary action: Forward a port (rules), Add NAT interface (NAT interfaces),
  none for active connections. Required content: rules (external ports, protocol, incoming
  interface, forward to, target port, Remove or the command explorer note for rules the NAT
  domain cannot express), translated interfaces with Remove, active connections (source,
  destination, translated address, protocol, interface, state, received, sent) in router
  pages of 200 with Previous and Next.
- Firewall. Primary action: Add rule (`Write`; a change to a list applied to the interface kcc
  reaches the router through asks first and runs inside the fail-safe timer, which needs
  `Destructive`). Priorities: 1 each list's rules in order, 2 where the list applies, 3 the IPv6
  lists or their note. Left out on purpose: drag-and-drop ordering, sorting or paging rules,
  traffic counters. Required content: per list its name, where it applies (interface and
  direction), Add rule and Apply to interface; per rule its position, action, protocol, source
  and destination (Any, an address, a network/prefix, a port), description, schedule, state,
  Move up and Move down, Enable or Disable, Description, Schedule, Remove; the IPv6 lists read
  only or the note linking the command explorer; the Interfaces view (interface, direction,
  list, Remove); the UPnP view, read only.

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Routing, port forwarding and firewall changes need JavaScript | `pages/routing.html`, `partials/routing_*.html`, `partials/nat_*.html`, `partials/firewall_*.html` | Dialogs, removals, moves and switches are htmx requests carrying the CSRF header; the tables, filters, sorting and pages work without it | Same as the menus |
| Tables of these pages scroll sideways on a phone with no edge fade or shadow | `.table-wrap` around `.routing-table` in `partials/routing_*.html`, `partials/nat_*.html`, `partials/firewall_*.html` | The shared `.table-wrap` has no scroll cue on any page, and a cue for this family alone would make tables differ between pages; a column cut at the edge is the only hint, and where a column ends right at the edge (active connections at 390 px) nothing shows that more follows | The page kit, for every `.table-wrap` at once |
| Connection states and route sources show the router's own words (established, boot) | State column of `partials/nat_sessions.html`, Source column of `partials/routing_table.html` | The firmware documents no list of these values, so a translation would be a guess that can name the wrong state; the DHCP leases page shows lease states the same way | The page kit and the domains, once the firmware documents the values |
## Presets and copying settings (todo 59, `src/presets_page/`)

The navigation gains Presets (`/ui/presets`) after Migration: the shell now has 14 links.

Layout (`/ui/presets`): stacked sections - page head (title, Copy settings and New preset
with `Migrate`), the intro, the outcome region, then the presets table in `.table-wrap
.presets-table` (positioned, so its visually hidden actions header stays inside the
sideways scroller); scroll owner: the document; nested scrollers: `.table-wrap`
(horizontal, the table only); anti-patterns: a card per preset, row actions in a
hover-only menu, controls for a role without `Migrate`.

Layout (`/ui/presets/new`, `/ui/presets/new/{draft}`): the wizard's single column - page
head, All presets, then `#wizard-step` with the migration wizard's source panel (kind
radios and only the chosen kind's field), then the groups panel: source facts, the group
checkboxes in a `repeat(auto-fill, minmax(min(100%, --presets-group-min), 1fr))` grid, the
captured settings (`#presets-captured`, swapped in place when a checkbox changes), name,
description and Save; scroll owner: the document; anti-patterns: a scrolling box for the
captured lines, a preview with a secret value.

Layout (`/ui/presets/{id}`): page head (name; Delete, Reveal secrets, Apply), All presets,
the facts, then one section per group (title with its count, the redacted lines); scroll
owner: the document.

Layout (`/ui/copy`, `/ui/presets/{id}/apply`, `/ui/presets/runs/{run}`): the migration
wizard's layouts and classes (`.wizard-steps`, `#wizard-step`, `.wizard-run`,
`.wizard-fate`, `.wizard-commands`), nine steps: source (fixed for a preset), target,
options, review, inputs, preview, apply, results, report.

Token: `--presets-group-min` (20rem, set on `.presets-groups`) is the narrowest a
settings-group checkbox column gets.

- Group checkboxes (`.presets-groups`, `.presets-group`): the kit's `.check` with the group
  name, its count (`.presets-group__count`, muted, tabular numerals) and its description
  as the field help.
- Captured settings (`.presets-captured`): an `h3`, the count as a `role="status"` line,
  then the lines (`.wizard-lines`, mono, redacted).
- Options: Merge or Mirror radios (`.choice`); the WireGuard checkbox (new keys, on by
  default) with the shared-key warning (`.wizard-warning`) always visible beside it; the
  names on the router in two `.wizard-map` tables (interfaces, policies), an empty field
  keeping the name.
- Review: the migration review's table; fates Sent (success pill), Already there,
  Not supported, Left out (neutral), Removed and Differs from the router (warning), Needs
  input (info); Apply checkboxes save as they change.
- Preview: counts, the ordered commands per phase (added, removed) with secret values
  redacted, Reveal secrets (`RevealSecrets`, audited, the plaintext only in its dialog)
  and Apply (asks in the dialog with the fail-safe minutes).
- Results: Keep unsaved (primary), Save on the router (secondary), Roll back
  (`button--danger-ghost`, the router name typed), Back to the preview and Finish when
  nothing waits; the countdown while the settings wait.
- Report: how it finished, the counts, the new WireGuard public keys (interface and key,
  mono) to register on the VPN servers, the kept-key warnings, the Markdown and JSON
  report.

### Page briefs (todo 59)

- Presets. Primary action: New preset (`Migrate`); Copy settings is secondary.
  Priorities: 1 the presets (name, groups), 2 where each came from and when, 3 Apply and
  Delete. Left out on purpose: line counts per row, stat tiles, a per-row preview.
  Required content: intro, name (link), groups, source (model, firmware, router, backup or
  file), captured time, creator, Apply and Delete (`Migrate` on the source router), the
  empty note.
- New preset. Primary action: Continue, then Save the preset. Priorities: 1 the groups
  and their counts, 2 the redacted captured settings, 3 name and description. Required
  content: kind, router, file, backup; source facts (source, model, firmware); every
  group with its count and description; the captured lines; name; description; the
  errors.
- Preset. Primary action: Apply (`Migrate`), in the page head beside Delete and Reveal
  secrets. Priorities: 1 where it came from (source, captured, creator, description), 2
  the settings per group. Required content: name, source, captured, creator,
  description, each group with its count and redacted lines, Reveal secrets
  (`RevealSecrets`), Delete (typed name).
- Apply and copy runs. Primary action: the step's own (Read the router, Continue, Preview
  the plan, Apply the settings, Review the result, Keep unsaved); Back is ghost. Required
  content per step: (1, copy) source router and groups; (2) target, facts, warnings, the
  tier acknowledgement, the older-firmware refusal; (3) Merge or Mirror, WireGuard keys
  with the shared-key warning, interface and policy names; (4) filters with counts, every
  setting with number, redacted text, fate, reason and Apply; (5) passwords; (6) counts,
  phases with commands, Reveal, Apply or why not; (7) Stop, progress, heartbeat, sent
  lines, the end; (8) result, counts, countdown, Keep unsaved / Save / Roll back /
  Back to the preview / Finish; (9) how it finished, when, counts, public keys, reports.

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Presets actions need JavaScript | `pages/presets_*.html`, `partials/presets_*.html` | Every change (save, delete, apply, the wizard's steps, Reveal) is an htmx request carrying the CSRF header; the lists, the preset page, the run pages and the report downloads work without it | Same as the menus |
| The captured settings update needs JavaScript | `partials/presets_compose.html` | Without htmx the captured lines stay as first shown; Save still captures exactly the checked groups | None needed |
| The presets list and the review table scroll sideways on a phone | `pages/presets_list.html`, `partials/presets_review.html` | Both use the shared `.table-wrap` pattern (the review is the migration review's `.wizard-review` table, at least `--wizard-review-min`); at 390 px the list's Created by, Apply and Delete and the review's Fate and Apply sit past the right edge with no scroll cue; the preset page repeats Apply and Delete | A stacked phone layout or a scroll cue shared by every `.table-wrap` table |

## Sign-in shell, router-aware navigation, segments list and delete (todo 70)

- Bare shell (`Shell::signed_out`, built by `prefs::shell`, so the sign-in page and its
  refused answer): the masthead keeps the brand and the language and theme menus; no Menu
  button, no fleet switcher or "no routers" note, no side navigation (five tab stops before
  the username instead of eighteen). Layout: one column, the masthead as "brand prefs"
  (`.masthead:not(:has(.masthead__menu))`) and the main area over the full width at 80rem
  (`.app:not(:has(> .sidenav))`); scroll owner: the document.
- Signing in or out through htmx answers `HX-Redirect`, a whole page load: a body swap kept
  the previous page's `<meta name="csrf-token">`, so the first change after signing in
  (the language menu above all) was refused with 403. Plain posts still get a 303.
- Language menu: on a signed-in page it carries `data-kcc-locale-action`, and `app.js`
  posts the choice to `/ui/account/locale` (CSRF header) before reloading, so the account
  and every live session of it change and the next page renders in the language; the
  cookie is still written for the sign-in page. A body swap (the account page's own save)
  takes `<html lang>` from the response. The account page now has the fleet switcher.
- Side navigation: Clients, Network, Wi-Fi, Routing, Firewall, DNS, VPN and System link to
  `/ui/r/{router}/<page>` (`Section::router_page`) for the router the page shows, else the
  only router in the fleet switcher; otherwise to `/ui/<section>`, the section's router
  picker (`pages/navpicker.html`). There is no remembered "last router": the fleet
  switcher is the only router state a page has.
- Router picker. Primary action: open the section on a router (the Pages link). Priorities:
  1 the routers the role may read, 2 the link to the section's page, 3 the link to each
  router's dashboard. Left out on purpose: router status and facts (the fleet overview has
  them), a "pick a router" sentence under the heading. Required content: the section title,
  Router and Pages columns, one row per readable router, the "no routers to open" and
  "not configured" notes. Anatomy and keys: the Clients, Configuration and Advanced
  landings.
- Segments page. Primary action: Create segment. Priorities: 1 the segments (bridge as the
  panel title, the Incomplete flag), 2 what each has (VLAN ID, address, DHCP range, NAT,
  new devices allowed, Wi-Fi, trunk ports, connection policy), 3 Delete. Left out on
  purpose: segments made outside kcc (the scope note sends readers to the Network page),
  per-segment edit (the domain has no segment edit), client counts. Required content: the
  family tabs, the router link, the outcome region, one `.panel` per segment with a
  `.facts` list in `.segments-list` (`#segments-region`, read back out of band after a
  create or a delete), Missing for an address or range a partial segment lost, the
  Incomplete flag and its note, the empty note, the scope note, Delete
  (`button--danger-ghost` in `.segments-actions`, `aria-describedby` the panel title) only
  where the role may delete. Layout: `repeat(auto-fill, minmax(min(100%, --panel-min),
  1fr))`, so a lone segment keeps a panel's width and every fact and Delete stay in view
  from 320 px up; a ten-column table pushed Delete past the right edge at 1280 px.
- Segment delete dialog: the kit's `TypedNameDialog` with `with_list`: the router objects
  that go (`SegmentView::delete_summary().owned_contexts`) and the ports that stay
  (`preserved_ports`, only the VLAN leaves them), each as `code` in a `.plain-list`; the
  router's name is typed; Delete segment is `button--danger`. The form posts to
  `.../segments/delete?id=&seen=`, where `seen` fingerprints the summary shown: a segment
  that changed answers the dialog again (422) with what goes now; a wrong name, or a hidden
  name that is not the router's, answers it with the field error; neither sends a change.
  Permission: `Write`, as the CLI and MCP delete (the typed name is the Web's
  confirmation).

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| The bare shell's layout uses `:has()` | `assets/css/app.css` | A browser without `:has()` keeps an empty navigation column on the sign-in page at 80rem and wider | None needed |
| A long fact value wraps under its label | `partials/segments_region.html` | The shared `.facts` row wraps a value that does not fit beside its label (a DHCP range at 390 px) onto its own line, start-aligned | A `.facts` variant that keeps wrapped values end-aligned, if the dashboard wants it too |
| Router picker links are text-sized | `pages/navpicker.html` | The router and section links are inline links in table cells (about 49x17 px at 320 px wide), the shape every landing table (Clients, Configuration, Advanced) uses; the rows are 49 px apart, so no other target sits within a 24 px circle (WCAG 2.5.8 spacing exception) | Taller row links if the landing tables change together |

WCAG 2.2 AA result for the todo-70 surfaces (probe `wcag.mjs` and `shots.mjs` in Chromium,
logged in `.omo/evidence/task-70-keenetic-control-center.log`):

| Check | Result | Evidence |
|---|---|---|
| Contrast 1.4.3/1.4.11 | PASS | Delete 7.08:1 light, 6.38:1 dark; fact labels 7.1:1 and 8.86:1; notes 7.81:1 and 10.59:1 |
| Focus 2.4.7/2.4.11 | PASS | Every stop of the sign-in page and Delete show the 2 px focus ring; the dialog opens on Close and Escape returns focus to Delete |
| Target size 2.5.8 | PASS | Masthead menus, fields, Sign in, Create segment, Delete, Close and Delete segment at least 44 px tall; picker links by the spacing exception |
| Keyboard 2.1.1/2.1.2 | PASS | Delete reached by Tab, the dialog by Enter, Escape closes it; no trap |
| Reflow and text spacing 1.4.10/1.4.12 | PASS | Sign-in, picker, segments and the delete dialog at 320 px in both themes and at 1280 px, with and without the text-spacing overrides: no sideways scroll, no clipping |
| Dragging, authentication, help, entry 2.5.7/3.3.8/3.2.6/3.3.7 | PASS | No drag; the sign-in page accepts paste and password managers (plain username and password fields); the typed router name is shown in the help text, not recalled |
| State-stable controls | PASS | Delete is 75x44 px idle, hovered and focused |
## Write-only secret fields (todo 71, `src/secret_pages/`)

Supersedes the "Left out on purpose" entries of the todo 37 and 40 briefs about passwords
(Wi-Fi password, connection password, router-account passwords: they are editable now)
and the todo 39 note that the import does not send keys and that VPN credentials have no
form.

Layout (secret dialog, `partials/secret_dialog.html`, `secret_pages::dialog::SecretDialog`):
the shared `<dialog>` as a centred modal - title, intro (what the secret is for), the
non-secret field when the secret needs one (an IKE key's name, a VPN account), New
password or New key, Type it again, the fail-safe note of a management change, Apply;
scroll owner: the dialog; nested scrollers: none; anti-patterns: a stored value or a mask
in a field (fields are always empty), the secret in a query string, a Reveal inside the
dialog, a confirmation dialog stacked over it (a management change's Apply is its
confirmation, the note above it says so).

- Secret input: the field anatomy (`.field`, label above, help and error below, described
  by both), `type="password"`, `autocomplete="new-password"`, `autocapitalize="none"`,
  `spellcheck="false"`, never a `value`; a length rule adds `minlength`, `maxlength` and
  the localized rule in `data-kcc-invalid` (`app.js` gives it to the browser's check, so
  an invalid value is never sent). The add-account dialog and the peer dialog use
  `kit::secret_field` the same way.
- Entry rule (`dialog::entry`): both fields empty keep the stored value and send nothing
  (outcome "Nothing was sent", audited `unchanged`); entries that differ come back as 422
  with the error under the repetition; the typed value moves into a `SecretString` and
  the repetition is zeroized.
- Outcome (`reply::verified`): a success toast names the field and says what the
  read-back checked (the router reports a stored value of a plausible length, never the
  value) and that the change stays unsaved; a failure stays in `#page-outcome` with the
  kit's words (`VerificationFailed` names the field).
- Refusal: the account kcc signs in with gets a warning notice instead of the form (GET)
  and the same notice as 422 (POST), before any router request.

Page briefs (todo 71):

- Wi-Fi password (`/ui/r/{router}/wifi/psk?name=`, from an access point's settings).
  Primary action: Apply. Priorities: 1 the new password, 2 its repetition, 3 the 8-63 rule.
  Left out on purpose: the current password (write-only), a show-password toggle, a
  strength meter. Required content: title with the access point, intro, New password with
  the rule as help, Type it again, Apply; the length error (client- and server-side).
- Connection password (`/ui/r/{router}/internet/password?name=`, PPP connections only).
  Primary action: Apply. Required content: title with the connection, New password,
  Type it again, the keep-empty help.
- Router account password (`/ui/r/{router}/system/users/password?name=`, row action Set
  password, hidden on kcc's own login). Primary action: Apply (management, confirms).
  Required content: title with the account, New password, Type it again, the fail-safe
  note; the refusal for kcc's login. The add-account dialog gains Password and Type it
  again (optional) in place of the old no-password note.
- VPN credentials (`/ui/r/{router}/vpn/credential?kind=&name=`): row actions Set password
  (L2TP/IPsec, PPTP, SSTP), Set IPsec key (L2TP/IPsec), Set pre-shared key and Set XAuth
  password (IPsec, per profile). Required content: title naming the connection or
  profile, New password or New key, Type it again.
- VPN servers: Set pre-shared key on the IPsec/IKEv2 panel (Key name, New key, Type it
  again) and Set an account's password on the User access panel (Account list without
  kcc's login, New password, Type it again, the fail-safe note).
- WireGuard peer dialog: Preshared key (optional, write-only) under the keepalive.
  WireGuard import: the file's keys are sent and verified; the success toast says so and
  the notes list only address, DNS and ASC.

Accessibility (section 8, todo 71): every secret input has a visible `<label for>`,
`type="password"` and `autocomplete="new-password"` (a password manager may fill it, paste
is never blocked), and `aria-describedby` naming its help and, after a refused try, its
error, with `aria-invalid="true"`; the refusal for kcc's own login is a `role="alert"`
notice. A length rule is also `minlength`/`maxlength`, so the browser refuses a short Wi-Fi
password before anything is sent.

| Item | Location | Why accepted | Owner / Exit |
|---|---|---|---|
| Secret dialogs need JavaScript | `partials/secret_dialog.html`, `partials/system_user_dialog.html`, `partials/dns_vpn_form.html` | The dialogs open and post through htmx with the CSRF header; without JavaScript the pages still show Set or Not set | Same as the menus |
| The localized length message needs JavaScript | `partials/secret_dialog.html` | Without `app.js` the browser shows its own message for a Wi-Fi password outside 8 to 63 characters; the server still refuses it with the localized rule before anything is sent | None needed |
