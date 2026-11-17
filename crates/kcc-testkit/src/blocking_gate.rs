//! A resource held by a plain thread, released only after the async runtime answers.
//!
//! A test proves that a call does not block the runtime's worker: the call waits on a
//! resource the gate holds (a pipe nobody wrote yet, a lock), and the gate gives the
//! resource up only once the runtime answered while the call was still waiting. On a
//! single-threaded runtime that answer can only come when the call waits off the worker;
//! a call that blocks the worker blocks the answer too, and the gate gives up after its
//! bound and reports that no answer came.

use core::time::Duration;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::PathBuf,
    sync::mpsc,
    thread,
};

use tokio::{sync::oneshot, task::spawn_blocking};

/// A resource held on a plain thread until the runtime answers or the bound passes.
#[derive(Debug)]
pub struct BlockingGate {
    /// Fires once the resource is in the state the call waits on.
    entered: Option<oneshot::Receiver<()>>,
    /// The runtime's answer.
    answer: mpsc::Sender<()>,
    /// The holding thread; it returns whether the answer came within the bound.
    holder: thread::JoinHandle<io::Result<bool>>,
}

impl BlockingGate {
    /// Holds the write end of the FIFO `pipe`: [`entered`](Self::entered) fires once a
    /// reader opened it. After the answer (or `bound`) the gate first puts a regular file
    /// with `bytes` in the FIFO's place, so a later read does not wait again, then writes
    /// `bytes` to the reader and closes.
    #[inline]
    #[must_use]
    pub fn pipe(pipe: PathBuf, bytes: Vec<u8>, bound: Duration) -> Self {
        let opened = pipe.clone();
        Self::hold(
            bound,
            move || OpenOptions::new().write(true).open(opened),
            move |mut writer| {
                let name = pipe
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned());
                let staged = pipe.with_file_name(format!(".{}.gate", name.unwrap_or_default()));
                fs::write(&staged, &bytes)?;
                fs::rename(&staged, &pipe)?;
                writer.write_all(&bytes)
            },
        )
    }

    /// Takes the resource with `take` on a plain thread: [`entered`](Self::entered) fires
    /// once it is taken; after the answer (or `bound`) the gate gives it back with `give`.
    #[inline]
    #[must_use]
    pub fn hold<R, T, G>(bound: Duration, take: T, give: G) -> Self
    where
        T: FnOnce() -> io::Result<R> + Send + 'static,
        G: FnOnce(R) -> io::Result<()> + Send + 'static,
    {
        let (entered_tx, entered) = oneshot::channel();
        let (answer, answers) = mpsc::channel();
        let holder = thread::spawn(move || {
            let resource = take()?;
            let _sent: Result<(), ()> = entered_tx.send(());
            let answered = answers.recv_timeout(bound).is_ok();
            give(resource)?;
            Ok(answered)
        });
        Self {
            entered: Some(entered),
            answer,
            holder,
        }
    }

    /// Waits until the resource is in the state the call waits on.
    ///
    /// # Errors
    ///
    /// Returns an error when the holding thread ended without taking it.
    // cancel-safe: only waits for a oneshot; dropped, the gate still releases after its bound.
    #[inline]
    pub async fn entered(&mut self) -> io::Result<()> {
        match self.entered.take() {
            Some(entered) => entered
                .await
                .map_err(|_closed| io::Error::other("the gate thread ended early")),
            None => Ok(()),
        }
    }

    /// Answers, waits for the gate to give the resource back, and returns whether the
    /// answer reached it while it still held the resource.
    ///
    /// # Errors
    ///
    /// Returns the holding thread's I/O error, or an error when it panicked.
    // cancel-safe: dropped, the holding thread still gives the resource back.
    #[inline]
    pub async fn release(mut self) -> io::Result<bool> {
        self.entered().await?;
        let _sent: Result<(), mpsc::SendError<()>> = self.answer.send(());
        let holder = self.holder;
        spawn_blocking(move || holder.join())
            .await
            .map_err(io::Error::other)?
            .map_err(|_panic| io::Error::other("the gate thread panicked"))?
    }
}
