//! The harness of the sign-in tests: accounts in a temporary state directory, sign-ins
//! on their own threads, and an observer that counts and holds their Argon2 runs.
#![expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]

extern crate alloc;

use alloc::{rc::Rc, sync::Arc};
use core::{cell::Cell, error::Error, time::Duration};
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::{Condvar, Mutex, MutexGuard, PoisonError, mpsc},
    thread,
    time::{Instant, SystemTime},
};

use secrecy::SecretString;
use tempfile::TempDir;

use super::super::{
    Account, AccountStore, Authentication, NewAccount, SystemClock, UsersDocument,
    hashing::probe::{self, Step, Work},
};
use crate::{
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};

pub(super) type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Longest wait for something that must happen.
pub(super) const WAIT: Duration = Duration::from_secs(30);

/// Tests that hold Argon2 runs open take turns, so one never waits on another's held runs.
static TURN: Mutex<()> = Mutex::new(());

pub(super) fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The password of account `name` in these tests, or a wrong one for any other word.
pub(super) fn password(word: &str) -> SecretString {
    SecretString::from(format!("{word} passphrase {}", process::id()))
}

pub(super) struct Fixture {
    _temp: TempDir,
    store: Arc<AccountStore>,
    users: PathBuf,
}

impl Fixture {
    /// Accounts `names` (role `viewer`, password `password(name)`) locking after
    /// `max_failures` failures.
    pub(super) fn new(
        max_failures: u32,
        names: &[&str],
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let users = state.dir().join("users.json");
        let store = AccountStore::new(
            state,
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::new(SystemClock),
        )
        .with_max_failures(max_failures);
        for &name in names {
            store.create(
                &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
                NewAccount::new(name.to_owned(), password(name), "viewer".to_owned()),
            )?;
        }
        Ok(Self {
            _temp: temp,
            store: Arc::new(store),
            users,
        })
    }

    /// The account store.
    pub(super) const fn store(&self) -> &Arc<AccountStore> {
        &self.store
    }

    /// The path of `users.json`.
    pub(super) fn users(&self) -> &Path {
        &self.users
    }

    /// Account `name` as stored now.
    pub(super) fn account(&self, name: &str) -> Result<Account, Box<dyn Error + Send + Sync>> {
        self.store
            .state
            .read::<UsersDocument>()?
            .unwrap_or_default()
            .users
            .into_iter()
            .find(|account| account.username == name)
            .ok_or_else(|| format!("no account {name}").into())
    }

    /// Signs in as `name` with `password(word)` on a new thread whose Argon2 runs
    /// `observed` watches.
    pub(super) fn sign_in(&self, observed: &Arc<Observed>, (name, word): (&str, &str)) -> Answer {
        let store = Arc::clone(&self.store);
        let watcher = Arc::clone(observed);
        let username = name.to_owned();
        let secret = password(word);
        on_thread(move || {
            watcher.watch();
            store
                .authenticate(&username, &secret)
                .map_err(|error| error.to_string())
        })
    }
}

/// The answer of work running on another thread.
pub(super) type Answer = mpsc::Receiver<Result<Authentication, String>>;

/// Runs `work` on a new thread; its result arrives on the returned channel.
pub(super) fn on_thread<T, F>(work: F) -> mpsc::Receiver<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    drop(thread::spawn(move || sender.send(work())));
    receiver
}

/// The file `path` as its identity, time, size and bytes.
pub(super) fn file(
    path: &Path,
) -> Result<(SystemTime, u64, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.modified()?, metadata.len(), fs::read(path)?))
}

/// What the watched Argon2 runs are doing.
#[derive(Debug, Default)]
pub(super) struct Board {
    /// Runs of the held kind in progress.
    running: usize,
    /// The most runs of the held kind seen in progress at once.
    most: usize,
    /// Threads waiting for a run slot.
    waiting: usize,
    /// Every run seen, in order.
    runs: Vec<Work>,
    /// Whether held runs may go on.
    released: bool,
}

impl Board {
    /// Runs of the held kind in progress.
    pub(super) const fn running(&self) -> usize {
        self.running
    }

    /// Threads waiting for a run slot.
    pub(super) const fn waiting(&self) -> usize {
        self.waiting
    }
}

/// Argon2 runs of several threads, of which those of one kind are held until released.
pub(super) struct Observed {
    held: Option<Work>,
    board: Mutex<Board>,
    changed: Condvar,
}

impl Observed {
    /// Watches runs, holding those of kind `held`.
    pub(super) fn new(held: Option<Work>) -> Arc<Self> {
        Arc::new(Self {
            held,
            board: Mutex::new(Board::default()),
            changed: Condvar::new(),
        })
    }

    fn board(&self) -> MutexGuard<'_, Board> {
        self.board.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Watches the current thread's runs.
    fn watch(self: &Arc<Self>) {
        let observed = Arc::clone(self);
        let waited = Cell::new(false);
        probe::install(Rc::new(move |step| observed.saw(step, &waited)));
    }

    fn saw(&self, step: Step, waited: &Cell<bool>) {
        let mut board = self.board();
        match step {
            Step::Waiting => {
                waited.set(true);
                board.waiting = board.waiting.saturating_add(1);
            }
            Step::Run(work) => {
                if waited.replace(false) {
                    board.waiting = board.waiting.saturating_sub(1);
                }
                board.runs.push(work);
                if self.held == Some(work) && !board.released {
                    board.running = board.running.saturating_add(1);
                    board.most = board.most.max(board.running);
                    self.changed.notify_all();
                    let start = Instant::now();
                    while !board.released {
                        let left = WAIT.saturating_sub(start.elapsed());
                        if left.is_zero() {
                            break;
                        }
                        board = self
                            .changed
                            .wait_timeout(board, left)
                            .unwrap_or_else(PoisonError::into_inner)
                            .0;
                    }
                    board.running = board.running.saturating_sub(1);
                }
            }
        }
        drop(board);
        self.changed.notify_all();
    }

    /// Waits at most [`WAIT`] until `ready` holds.
    pub(super) fn until(&self, what: &str, ready: impl Fn(&Board) -> bool) -> Result<(), String> {
        let start = Instant::now();
        let mut board = self.board();
        while !ready(&board) {
            let left = WAIT.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(format!("timed out waiting until {what}: {board:?}"));
            }
            board = self
                .changed
                .wait_timeout(board, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        drop(board);
        Ok(())
    }

    /// The most held runs seen in progress at once.
    pub(super) fn most(&self) -> usize {
        self.board().most
    }

    /// Every run seen, in order.
    pub(super) fn runs(&self) -> Vec<Work> {
        self.board().runs.clone()
    }

    /// Lets every held run go on, and every later one through.
    pub(super) fn release(&self) {
        self.board().released = true;
        self.changed.notify_all();
    }
}

/// Whether this machine can run two Argon2 checks at once, which these tests need.
pub(super) fn slots() -> Result<usize, Box<dyn Error + Send + Sync>> {
    let slots = thread::available_parallelism()?.get();
    if slots < 2 {
        return Err("these tests need two CPUs".into());
    }
    Ok(slots)
}
