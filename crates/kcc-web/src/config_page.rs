//! The configuration and backups page of a router, built on the domain page kit.
//!
//! It shows whether the running configuration has unsaved changes (with Save), the
//! router's fail-safe timer (with Keep changes and Roll back while it runs), and the
//! router's encrypted backups: created by the change workflow before changes, on this page
//! or uploaded as a startup-configuration file. A backup downloads with its secrets only
//! for `RevealSecrets`, otherwise without them (no `ns3` blob, no registered secret); two
//! backups, or a backup and the running configuration, compare server-side as the
//! configuration lines that changed, secrets replaced. A backup restores through the
//! migration wizard (plan review first) or, same model only, as a raw restore.
//!
//! Routes (route table: `Read` and the router's scope, except `/ui/configuration`
//! (`Write`) and `.../save` (`Save`); every action re-checks its own permissions):
//!
//! - `GET /ui/configuration`: every router the user may read, with its configuration page.
//! - `GET /ui/r/{router}/config[?q=&sort=&dir=&page=]`: the page.
//! - `POST /ui/r/{router}/config/save` (`Save`), `POST .../commit` (`Save`, while the
//!   fail-safe timer runs), `POST .../rollback` (`Destructive`, router name typed).
//! - `POST /ui/r/{router}/config/backups`: a backup of the saved configuration (`Write`).
//! - `GET /ui/r/{router}/config/upload`: the upload dialog; `POST .../backups/upload`: a
//!   startup-configuration file of at most 1 MiB stored as a backup (`Write`, multipart).
//! - `GET /ui/r/{router}/config/backups/download?name=[&full=yes]`: the backup without
//!   its secrets (`Read`), or as stored (`RevealSecrets`); audited either way.
//! - `POST /ui/r/{router}/config/backups/delete?name=` (`Destructive`, router name
//!   typed) and `POST .../backups/raw-restore?name=` (`Destructive` and `Migrate`, router
//!   name typed, same hardware only).
//! - `GET /ui/r/{router}/config/diff?from=&to=&view=`: two configurations compared.

mod backup_rows;
mod backups;
mod compare;
mod compare_view;
mod confirm;
mod create;
mod diff;
mod download;
mod landing;
mod page;
mod raw;
mod restore;
mod safety;
mod status;
mod store;
mod text;
mod upload;
mod upload_check;
pub(crate) mod wiring;
