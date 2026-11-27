//! What the scheduler tells the notifier: its lines, the routers it restarts and the jobs
//! it starts (whose failures it reports itself).

use core::fmt::Debug;

use crate::{server_notify::NotifyHandle, server_schedules::lines::Line};

/// The notifier as the scheduler uses it.
pub(crate) trait Notices: Debug + Send + Sync {
    /// Queues `line` when its event is selected.
    fn send_line(&self, line: Line);

    /// Mutes `router`'s offline and online messages until `until` (Unix seconds).
    fn mute_router(&self, router: &str, until: u64);

    /// Claims job `id`: its failure is the scheduler's to report.
    fn claim_job(&self, id: String);
}

impl Notices for NotifyHandle {
    fn send_line(&self, line: Line) {
        let named = self.router_name(line.router());
        self.report(line.event(), move |locale| line.render(locale, &named));
    }

    fn mute_router(&self, router: &str, until: u64) {
        self.mute(router, until);
    }

    fn claim_job(&self, id: String) {
        self.scheduled_jobs().register(id);
    }
}
