//! Settings presets at `/ui/presets` and copying settings at `/ui/copy`.
//!
//! A preset is a named, encrypted set of settings groups (`kcc_migrate::presets`) captured
//! from a router, a stored backup or an uploaded startup-config file. The route table
//! gives these pages `Read`; capturing, deleting and applying need `Migrate` on the
//! preset's source router, and applying `Migrate` on the target too, checked by every
//! handler before anything else.
//!
//! Applying a preset (`/ui/presets/{id}/apply`) and copying settings once (`/ui/copy`,
//! a transient preset sealed in the run's directory and deleted when the run finishes or
//! after 24 hours) share one wizard on the wizard engine (`crate::wizard`): runs are kept in
//! `<state>/migrations/<id>/` (record `preset.json`), secrets are sealed with the backup
//! key, the apply is followed live over server-sent events, and only one run applies to
//! a router at a time.
//!
//! Routes:
//!
//! - `GET /ui/presets`: the presets; `GET /ui/presets/new`, `POST /ui/presets/new`
//!   (multipart): a new preset's source; `GET /ui/presets/new/{draft}`, `POST` (save),
//!   `POST .../preview`: its groups, the redacted captured settings, name and description.
//! - `GET /ui/presets/{id}`: one preset, redacted; `POST .../reveal` (`RevealSecrets`,
//!   audited), `POST .../delete` (typed name).
//! - `GET`/`POST /ui/presets/{id}/apply` and `GET`/`POST /ui/copy`: the runs and starting
//!   one.
//! - `GET /ui/presets/runs/{run}` and its step posts, `GET .../events` (the live apply),
//!   `GET .../download/{report.json,report.md}`.

mod access;
mod apply;
mod capture;
mod compose;
mod compose_panel;
mod delete;
mod detail;
mod downloads;
mod drafts;
mod events;
mod fates;
mod finish;
mod inputs;
mod landing;
mod launch;
mod lines;
mod list;
mod options;
mod plan;
mod preview;
mod record;
mod resume;
mod reveal;
mod review;
mod review_submit;
pub(crate) mod routes;
mod saved;
mod source;
mod steps;
mod summary;
mod target;
mod target_submit;
