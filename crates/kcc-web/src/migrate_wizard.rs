//! The migration wizard at `/ui/migrate` (route table: `Migrate`; every router it names
//! must be in the role's `Migrate` scope).
//!
//! Nine steps move a configuration from a router, an uploaded startup-config or a stored
//! backup to a target router: source, target (with its warnings), inventory and maps,
//! review, inputs, preview, apply (followed live), results (commit or roll back) and the
//! report. Each migration's choices are kept in `<state>/migrations/<id>/` so a reload
//! resumes it; its secrets are sealed there with the backup key and never stored in the
//! clear. A restore (`/ui/migrate?mode=restore&router=<id>&backup=<name>`) applies a
//! stored backup to its own router through the same reviewed plan.
//!
//! Routes:
//!
//! - `GET /ui/migrate[?mode=restore&router=&backup=]`, `POST /ui/migrate`: the user's
//!   migrations and starting one (or the offered restore).
//! - `GET /ui/migrate/{id}`: the migration at its current step; `POST .../back` shows an
//!   earlier one.
//! - `POST /ui/migrate/{id}/source` (multipart), `.../target`, `.../target/continue`,
//!   `.../mapping`: steps 1 to 3.
//! - `POST /ui/migrate/{id}/review` (saves the shown page's choices), `.../review/continue`,
//!   `.../inputs`: steps 4 and 5; `GET .../download/{plan.json,report.json,report.md,
//!   report.html}`: step 6's files.
//! - `POST /ui/migrate/{id}/apply` (asks first), `.../stop`, `.../results`: step 7; the
//!   stream `GET .../events[?view=countdown]` follows the apply (outside the timeout).
//! - `POST /ui/migrate/{id}/commit`, `.../rollback` (router name typed), `.../replan`,
//!   `.../retry`, `.../close`: step 8; step 9 shows the report.

mod access;
mod analysis;
mod apply;
mod apply_request;
mod beats;
mod confirm;
mod downloads;
mod events;
mod finish;
mod ids;
mod inputs;
mod inputs_submit;
mod kinds;
mod landing;
mod launch;
mod live;
mod mapping;
mod mapping_submit;
mod maps;
mod names;
mod needs;
mod plan;
mod preview;
mod reasons;
mod record;
mod report;
mod results;
mod resume;
mod review;
mod review_submit;
pub(crate) mod routes;
mod run;
mod running;
mod screen;
mod service;
mod source;
mod source_read;
mod store;
mod target;
mod target_confirm;
mod warnings;
