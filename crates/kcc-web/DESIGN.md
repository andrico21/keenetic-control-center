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
placeholder 4.6 / 6.4, link 5.0 / 7.7, on-accent 5.0, every status ink >= 4.8 on its wash,
field edge 3.3 / 4.6.

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

`--setting-label` (12rem) is the widest label column of a settings list.

Layout (system general `/ui/r/{router}/system/general`, the domain page kit's reference):
stacked sections - page head, router link, the outcome region (hidden while empty), the
settings panels in the dashboard's `repeat(auto-fit, minmax(min(100%, --panel-min), 1fr))`
grid (identity, time), then the restart panel; scroll owner: the document; anti-patterns: a
success banner repeating its toast, settings rows whose height depends on their button, an
Edit button for a setting the page cannot change.

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
- Tones by wash: success (default), info, error, neutral; `notice__title` for a bold first
  line. A `role="note"` notice is one paragraph (the tier notice with its link).

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
  zone, router clock, time synchronization), 3 restart. Left out on purpose: uptime and
  firmware (the dashboard has them), factory reset, time-zone and NTP changes (todo 40).
  Required content: host name with Edit (`Write`), description with Edit (`Write`), domain
  name, time zone, router clock, time synchronization or "Not reported", Restart router
  (`Destructive`, router name typed), the outcome region.

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
