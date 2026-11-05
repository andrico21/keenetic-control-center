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
- Lazyweb: skipped - todo 33 builds the shell and primitives only, no product screen yet;
  run it with the first data page (todo 35).
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
| Selection | `--color-selection` | #0f62fe 20% | #78a9ff 30% | `::selection` |
| Scrim | `--color-scrim` | #161616 50% | #000000 60% | Dialog and sheet backdrop |
| Shadow | `--color-shadow` | #000000 20% | #000000 60% | Floating surfaces only |

Measured contrast (WCAG 2.x): text 18.1 / 16.5, muted 7.8 / 10.6 (7.1 / 8.9 on chrome),
placeholder 4.6 / 6.4, link 5.0 / 7.7, on-accent 5.0, every status ink >= 4.8 on its wash,
field edge 3.3 / 4.6.

Rules: accent fills only the primary action; the current place uses the selected wash and ink;
status colour lives only in pills, badges, toasts and field errors.

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
`--sidenav-width` is 15rem. Breakpoints: compact < 48rem, medium >= 48rem (masthead on one
row), wide >= 80rem (persistent side navigation).

Layout: app shell - persistent section navigation beside long admin pages -> sticky-aside
(https://github.com/changeroa/StyleGallery/blob/main/patterns/split-sidebar/sticky-aside.md);
scroll owner: the document (`html`); the navigation list sticks at the top of its column and
scrolls itself only when taller than the viewport; below 80rem the navigation is a popover
sheet opened by the Menu button; anti-patterns: a second scroll container for `main`,
`100vh` heights, a visual order different from DOM and focus order.

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

### Toast (`ui::toast`)
- Structure: `#toasts` `role="status"` `aria-live="polite"` region; each toast has a message
  and a Close button; tone by wash (info, success, warning, error), never by an edge stripe.

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
