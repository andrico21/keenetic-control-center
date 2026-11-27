//! `GET /ui/r/{router}/config/diff?from=&to=&view=`: two configurations compared, a
//! backup with another backup or with the router's running configuration.
//!
//! Both sides are read on the server, flattened and compared by the digest of each
//! command; the page shows exactly the lines that changed, with every secret replaced,
//! unified (`view=unified`, the default) or side by side (`view=split`).

use core::str;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
};
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use tokio::task::spawn_blocking;

use super::{
    backup_rows::BackupRow,
    compare_view::{CompareForm, RUNNING, ShownChanges},
    page::Visit,
    store::{self, StoreError},
    text::Lines,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller, Target},
        family::Family,
        read_failure::{ReadProblem, rci_problem, registry_problem},
    },
};

/// The comparison a request asks for.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct DiffQuery {
    /// The older side: a backup's file name.
    #[serde(default)]
    from: Option<String>,
    /// The newer side: a backup's file name or `running`.
    #[serde(default)]
    to: Option<String>,
    /// `split` for side by side.
    #[serde(default)]
    view: Option<String>,
}

/// The diff page.
#[derive(Template)]
#[template(path = "pages/config_diff.html")]
struct DiffPage {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The comparison form, with the chosen sides.
    form: Option<CompareForm>,
    /// What the older side is.
    from_label: String,
    /// What the newer side is.
    to_label: String,
    /// The changes, once both sides were read.
    changes: Option<ShownChanges>,
    /// Why the comparison could not be shown.
    problem: Option<ReadProblem>,
    /// What to do first, when nothing was compared yet.
    note: Option<MessageKey>,
    /// Whether the changes show side by side.
    split: bool,
}

localized!(DiffPage);

impl DiffPage {
    /// What was compared with what, as a heading.
    fn heading(&self) -> String {
        let mut args = FluentArgs::new();
        args.set("first", self.from_label.clone());
        args.set("last", self.to_label.clone());
        tr(
            self.shell.locale(),
            keys::WEB_CONFIG_DIFF_BETWEEN,
            Some(&args),
        )
    }

    /// A count of lines, as people read it.
    fn count(&self, lines: usize) -> String {
        format::integer(
            self.shell.locale(),
            u64::try_from(lines).unwrap_or(u64::MAX),
        )
    }
}

/// `GET /ui/r/{router}/config/diff`: the comparison the query asks for.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<DiffQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Configuration, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let split = query.view.as_deref() == Some("split");
    let mut page = DiffPage {
        shell,
        router: router.clone(),
        form: None,
        from_label: String::new(),
        to_label: String::new(),
        changes: None,
        problem: None,
        note: None,
        split,
    };
    if let Err(problem) = compare(
        &mut page,
        (target, Visit::new(&state, &user, &router)),
        &query,
    )
    .await
    {
        page.problem = Some(problem);
    }
    errors::render(&page)
}

/// Fills `page` with the comparison `query` asks for.
///
/// # Errors
///
/// Returns why the comparison cannot be shown.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn compare(
    page: &mut DiffPage,
    (target, visit): (Target<'_>, Visit<'_>),
    query: &DiffQuery,
) -> Result<(), ReadProblem> {
    let services = visit.backups().ok_or(keys::WEB_CONFIG_NO_STORE)?;
    let listed = store::list(services, visit.router())
        .await
        .map_err(|_error| keys::WEB_CONFIG_STORE_FAILED)?;
    let locale = visit.user().locale();
    let rows: Vec<BackupRow> = listed
        .into_iter()
        .map(|info| BackupRow::new(info, locale, visit.now()))
        .collect();
    let form = CompareForm::new(locale, visit.router(), &rows);
    let (Some(from), Some(to)) = (query.from.as_deref(), query.to.as_deref()) else {
        page.note = Some(if rows.is_empty() {
            keys::WEB_CONFIG_DIFF_NO_BACKUPS
        } else {
            keys::WEB_CONFIG_DIFF_CHOOSE
        });
        page.form = Some(form);
        return Ok(());
    };
    let from_label = form.label(from).map(str::to_owned);
    let to_label = if to == RUNNING {
        Some(tr(locale, keys::WEB_CONFIG_RUNNING, None))
    } else {
        form.label(to).map(str::to_owned)
    };
    page.form = Some(form.chosen((from, to), page.split));
    let (Some(older), Some(newer)) = (from_label, to_label) else {
        return Err(keys::WEB_CONFIG_DIFF_MISSING.into());
    };
    page.from_label = older;
    page.to_label = newer;
    let old = side(target, visit, from).await?;
    let new = side(target, visit, to).await?;
    page.changes = Some(changes(old, new).await?);
    Ok(())
}

/// The changes from `old` to `new`, computed on the blocking pool: comparing two large
/// configurations is CPU-bound work an async worker must not carry.
///
/// # Errors
///
/// Returns the unreadable notice when the task died.
// cancel-safe: pure computation; a dropped caller leaves it to end unseen.
async fn changes(old: Lines, new: Lines) -> Result<ShownChanges, MessageKey> {
    spawn_blocking(move || ShownChanges::new(&old, &new))
        .await
        .map_err(|error| {
            tracing::error!(%error, "configuration comparison task failed");
            keys::WEB_CONFIG_DIFF_UNREADABLE
        })
}

/// The commands of one side: a backup of the router, or its running configuration.
///
/// # Errors
///
/// Returns why the side cannot be read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn side(target: Target<'_>, visit: Visit<'_>, choice: &str) -> Result<Lines, ReadProblem> {
    let text = if choice == RUNNING {
        let client = target
            .fleet()
            .registry()
            .client(visit.router())
            .await
            .map_err(|error| registry_problem(Family::Changes, &error))?;
        let bytes = client
            .download_config(ConfigKind::Running)
            .await
            .map_err(|error| rci_problem(Family::Changes, &error))?;
        let plain = str::from_utf8(bytes.expose_secret())
            .map_err(|_error| keys::WEB_CONFIG_DIFF_UNREADABLE)?;
        SecretString::from(plain.to_owned())
    } else {
        let services = visit.backups().ok_or(keys::WEB_CONFIG_NO_STORE)?;
        store::read(services, visit.router(), choice)
            .await
            .map_err(|error| match error {
                StoreError::Missing => keys::WEB_CONFIG_DIFF_MISSING,
                StoreError::Failed => keys::WEB_CONFIG_STORE_FAILED,
            })?
    };
    Lines::read(text.expose_secret()).map_err(|_error| keys::WEB_CONFIG_DIFF_UNREADABLE.into())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation and fails by panicking"
)]
mod tests {
    use std::sync::mpsc;

    use futures_util::FutureExt as _;
    use tokio::{runtime::Builder, sync::oneshot, task::spawn_blocking};

    use super::{Lines, changes};

    /// W2-07: with the blocking pool's only thread busy the comparison cannot finish, so
    /// it does not run on the caller's thread; it completes once the pool is free.
    #[test]
    fn the_comparison_runs_on_the_blocking_pool() {
        let runtime = Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (release, held) = mpsc::channel::<()>();
            let (entered_tx, entered) = oneshot::channel::<()>();
            let busy = spawn_blocking(move || {
                let _sent: Result<(), ()> = entered_tx.send(());
                let _released: Result<(), mpsc::RecvError> = held.recv();
            });
            entered.await.expect("the pool thread is busy");
            let old = Lines::read("system\n description a\n!\n").expect("old");
            let new = Lines::read("system\n description b\n!\n").expect("new");
            let mut comparison = Box::pin(changes(old, new));
            assert!(
                (&mut comparison).now_or_never().is_none(),
                "the comparison waits for the pool"
            );
            let _sent: Result<(), mpsc::SendError<()>> = release.send(());
            busy.await.expect("released");
            assert!(comparison.await.is_ok(), "then completes");
        });
    }
}
