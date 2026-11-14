//! The wizard engine the migration wizard (`crate::migrate_wizard`) and the presets' apply
//! runs (`crate::presets_page`) share.
//!
//! Each wizard is a [`flow::Flow`]: its steps, its record and its pages. The engine keeps
//! every run's files under `<state>/migrations/<id>/` (`store`, `ids`) and its in-memory
//! side (`service`), opens a run for one request (`services`, `visit`), and moves every
//! wizard through the same steps: the record's step machine (`flow`), the page around a
//! step's panel (`screen`), resuming at the current step, Back and the result (`resume`),
//! the apply followed live with Stop (`running`, `live`, `run`, `events`, `beats`) and
//! the report (`report`); `analysis` holds what both wizards' analyses share.

pub(crate) mod analysis;
pub(crate) mod beats;
pub(crate) mod events;
pub(crate) mod flow;
pub(crate) mod ids;
pub(crate) mod live;
pub(crate) mod report;
pub(crate) mod resume;
pub(crate) mod run;
pub(crate) mod running;
pub(crate) mod screen;
pub(crate) mod service;
pub(crate) mod services;
pub(crate) mod store;
pub(crate) mod visit;
