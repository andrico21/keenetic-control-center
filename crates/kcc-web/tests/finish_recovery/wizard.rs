//! The two wizards that finish an apply, driven alike to their results.

use axum::http::StatusCode;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::FaultInjection;

use crate::{
    migration_flow, migration_setup, preset_flow, preset_setup,
    support::{
        outcome::TestResult,
        web::{Browser, Fixture},
    },
};

/// A wizard that applies onto a target and finishes there.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Wizard {
    /// A migration from `prod-1`'s saved source onto `ultra`.
    Migration,
    /// A preset captured on `prod-1`, applied onto `lab-1`.
    Preset,
}

impl Wizard {
    /// Both wizards.
    pub(crate) const ALL: [Self; 2] = [Self::Migration, Self::Preset];

    /// The target router's profile id, typed to roll back.
    pub(crate) const fn target(self) -> &'static str {
        match self {
            Self::Migration => "ultra",
            Self::Preset => "lab-1",
        }
    }

    /// The route segment that keeps the applied changes.
    pub(crate) const fn keep(self) -> &'static str {
        match self {
            Self::Migration => "commit",
            Self::Preset => "save",
        }
    }

    /// The audit action of keeping (or, with `rollback`, of rolling back).
    pub(crate) const fn audited(self, rollback: bool) -> &'static str {
        match (self, rollback) {
            (Self::Migration, false) => "web.migrate_commit",
            (Self::Migration, true) => "web.migrate_rollback",
            (Self::Preset, false) => "web.preset_save",
            (Self::Preset, true) => "web.preset_rollback",
        }
    }

    /// What the apply's stream says when it verified the changes.
    pub(crate) const fn applied(self) -> MessageKey {
        match self {
            Self::Migration => keys::MIGRATE_APPLY_VERIFIED,
            Self::Preset => keys::WEB_PRESETS_APPLIED,
        }
    }

    /// A fixture whose target reports `mode` and has `faults`, with the wizard applied
    /// and at its results; returns the fixture, the admin and the run's page.
    ///
    /// # Errors
    /// Returns request failures of the steps, an apply that is not verified and results
    /// that do not open.
    // NOT cancel-safe: the fixture applies settings onto the target.
    pub(crate) async fn at_results(
        self,
        mode: &str,
        faults: FaultInjection,
    ) -> TestResult<(Fixture, Browser, String)> {
        let (fixture, admin, page) = match self {
            Self::Migration => {
                let fixture = migration_setup::with_mode(mode, faults).await?;
                migration_flow::seed_source(&fixture).await?;
                let admin = fixture.login("admin").await?;
                let page = migration_flow::to_review(&fixture, &admin).await?;
                migration_flow::to_preview(&fixture, &admin, &page).await?;
                (fixture, admin, page)
            }
            Self::Preset => {
                let fixture = preset_setup::with_mode(mode, faults).await?;
                preset_flow::seed(&fixture, "prod-1", &preset_flow::DNS_LINES).await?;
                let admin = fixture.login("admin").await?;
                let captured = ("dns-secure", "Closing DNS");
                let id =
                    preset_flow::capture(&fixture, &admin, "prod-1", (&[captured.0], captured.1))
                        .await?;
                let page = preset_flow::start(&fixture, &admin, &id).await?;
                let choice = (self.target(), "merge", &[][..]);
                preset_flow::to_preview(&fixture, &admin, &page, choice).await?;
                (fixture, admin, page)
            }
        };
        let stream = match self {
            Self::Migration => migration_flow::apply(&fixture, &admin, &page).await?,
            Self::Preset => preset_flow::apply(&fixture, &admin, &page).await?,
        };
        if !stream.contains(&tr(Locale::En, self.applied(), None)) {
            return Err(format!("{self:?}: the apply is not verified: {stream}").into());
        }
        let results = fixture
            .post_form(&format!("{page}/results"), &admin, &[])
            .await?;
        if results.status() != StatusCode::OK {
            return Err(format!("{self:?}: results answered {}", results.status()).into());
        }
        Ok((fixture, admin, page))
    }

    /// The rollback's confirmation: the button and the target's name.
    pub(crate) const fn rollback_form(self) -> [(&'static str, &'static str); 2] {
        [("confirm", "yes"), ("confirm_name", self.target())]
    }
}
