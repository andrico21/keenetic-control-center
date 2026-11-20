//! The outbox task: one loop over commands, settings, the send in flight and the next
//! due message. At most one message is in flight at a time.

use core::{fmt, future::pending, pin::Pin};

use kcc_app::notify_store::{
    DisabledReason,
    recipients::{Chat, ChatId},
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use self::state::Delivery;
use super::{Line, Parts, pacing::Batch, persist};
use crate::notify::{bot::Sent, failure::SendError};

mod access;
mod books;
mod state;

/// The answer channel of a test message.
type Reply = oneshot::Sender<Result<(), SendError>>;
/// A send in progress.
type Sending = Pin<Box<dyn Future<Output = Result<Sent, SendError>> + Send>>;

/// A request to the task.
pub(super) enum Command {
    /// Queue a line.
    Push(Line),
    /// Send a test message.
    SendNow {
        /// Target chat.
        chat: Chat,
        /// Text.
        text: String,
        /// Where the outcome goes.
        reply: Reply,
    },
    /// Ignore merge windows until idle; answered once the task has seen it.
    Flush(oneshot::Sender<()>),
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Command")
    }
}

/// The token, chats and switch of one `configure` call.
#[derive(Clone, Default)]
pub(super) struct Settings {
    /// Bot token.
    token: Option<SecretString>,
    /// Configured chats.
    chats: Vec<Chat>,
    /// Notifications on.
    enabled: bool,
}

impl Settings {
    /// Bundles one `configure` call.
    pub(super) const fn new(token: Option<SecretString>, chats: Vec<Chat>, enabled: bool) -> Self {
        Self {
            token,
            chats,
            enabled,
        }
    }

    /// Whether `next` brings a token other than this one.
    fn other_token(&self, next: &Self) -> bool {
        match (self.token.as_ref(), next.token.as_ref()) {
            (Some(old), Some(new)) => old.expose_secret() != new.expose_secret(),
            (None, None) => false,
            (Some(_), None) | (None, Some(_)) => true,
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("token", &self.token.as_ref().map(|_set| "[REDACTED]"))
            .field("chats", &self.chats.len())
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// A test message waiting for its chat's rate limit.
struct Test {
    /// Target chat.
    chat: Chat,
    /// Text.
    text: String,
    /// Where the outcome goes.
    reply: Reply,
}

/// What a message in flight carries.
enum Cargo {
    /// Queued lines, put back on a retryable failure.
    Lines(Batch),
    /// A test message's answer channel.
    Test(Reply),
}

/// A state-file write a delivery outcome asks for.
enum Record {
    /// Nothing to write.
    Nothing,
    /// Telegram refused the token.
    TokenRejected,
    /// Telegram refused a chat.
    Disabled(ChatId, DisabledReason),
}

/// The message in flight.
struct Flight {
    /// Its chat.
    chat: ChatId,
    /// Its lines or answer channel.
    cargo: Cargo,
    /// The request.
    sending: Sending,
}

/// One wake-up of the loop.
enum Event {
    /// Stop: cancelled or every handle dropped.
    Stop,
    /// The send in flight ended.
    Finished(Result<Sent, SendError>),
    /// New settings.
    Settings,
    /// A command.
    Command(Command),
    /// A message may be due.
    Due,
}

/// Waits for the send in flight; never resolves without one.
///
/// # Errors
///
/// The send's [`SendError`].
// cancel-safe: the boxed request lives in `flight`, so dropping this wait loses nothing.
async fn in_flight(flight: &mut Option<Flight>) -> Result<Sent, SendError> {
    match flight.as_mut() {
        Some(current) => current.sending.as_mut().await,
        None => pending().await,
    }
}

/// Sleeps until `wake`; never resolves without one.
// cancel-safe: a timer.
async fn sleep_until_some(wake: Option<Instant>) {
    match wake {
        Some(at) => sleep_until(at).await,
        None => pending().await,
    }
}

/// Runs the outbox until `cancel` fires or every handle is dropped.
// NOT cancel-safe: dropping it abandons the queued lines and the send in flight.
pub(super) async fn run(
    parts: Parts,
    mut commands: mpsc::Receiver<Command>,
    mut settings: watch::Receiver<Settings>,
    cancel: CancellationToken,
) {
    let mut delivery = Delivery::new(parts.timings, parts.metrics.clone());
    let mut flight: Option<Flight> = None;
    loop {
        drop(parts.status.send_replace(delivery.status(flight.is_some())));
        let wake = if flight.is_none() {
            delivery.next(Instant::now()).map(|(at, _)| at)
        } else {
            None
        };
        let event = tokio::select! {
            biased;
            () = cancel.cancelled() => Event::Stop,
            result = in_flight(&mut flight) => Event::Finished(result),
            changed = settings.changed() => changed.map_or(Event::Stop, |()| Event::Settings),
            command = commands.recv() => command.map_or(Event::Stop, Event::Command),
            () = sleep_until_some(wake) => Event::Due,
        };
        match event {
            Event::Stop => break,
            Event::Finished(result) => {
                if let Some(done) = flight.take() {
                    let now = Instant::now();
                    let record =
                        delivery.finish((done.chat, done.cargo), result, (now, &parts.config));
                    match record {
                        Record::Nothing => {}
                        Record::TokenRejected => persist::token_rejected(&parts.store).await,
                        Record::Disabled(chat, reason) => {
                            persist::disable(&parts.store, chat, reason).await;
                        }
                    }
                }
            }
            Event::Settings => {
                let current = settings.borrow_and_update().clone();
                let runtime = persist::read(&parts.store).await;
                let cleared = delivery.ends_refusal(&current);
                let listed = delivery.configure(current, &runtime);
                persist::forget(&parts.store, listed, cleared).await;
            }
            Event::Command(Command::Push(line)) => delivery.push(&line, Instant::now()),
            Event::Command(Command::SendNow { chat, text, reply }) => {
                delivery.test(chat, text, reply);
            }
            Event::Command(Command::Flush(seen)) => {
                delivery.flush();
                drop(parts.status.send_replace(delivery.status(flight.is_some())));
                let _unheard: Result<(), ()> = seen.send(());
            }
            Event::Due => {
                flight = delivery
                    .start(Instant::now())
                    .map(|(chat, cargo, message, token)| {
                        let client = parts.client.clone();
                        let sending: Sending =
                            Box::pin(async move { client.send(&token, &message).await });
                        Flight {
                            chat,
                            cargo,
                            sending,
                        }
                    });
            }
        }
    }
    delivery.stop();
}
