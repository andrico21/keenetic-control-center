//! The SSH side of the fake: accept loop, authentication and exec requests.

use alloc::sync::Arc;
use core::time::Duration;

use russh::{
    Channel, ChannelId, MethodKind, MethodSet,
    keys::PublicKey,
    server::{self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey},
};
use subtle::ConstantTimeEq as _;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

use super::{Fault, HUGE_OUTPUT_LINE, HUGE_OUTPUT_LINES, Reply, Shared, State, USER, command};

/// Accepts connections until `stopped` fires or its sender is dropped; dropping the
/// returned future drops every connection.
// cancel-safe: dropped, it closes the listener and every connection; no state is lost.
pub(super) async fn serve(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _signal = &mut stopped => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => {
                    let config = connection_config(&shared);
                    let handler = Connection { shared: Arc::clone(&shared) };
                    drop(sessions.spawn(session(config, stream, handler)));
                }
                Err(error) => tracing::debug!(%error, "fake Entware SSH accept failed"),
            },
            Some(_finished) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

/// Counts a new connection and builds its server configuration with the current host key.
fn connection_config(shared: &Shared) -> Arc<server::Config> {
    let mut state = shared.lock();
    state.counters.connections = state.counters.connections.saturating_add(1);
    Arc::new(server::Config {
        keys: vec![state.host_key.clone()],
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    })
}

/// Runs one SSH connection until the client leaves or the fake drops it.
// cancel-safe: dropped, it closes the connection.
async fn session(config: Arc<server::Config>, stream: TcpStream, handler: Connection) {
    match server::run_stream(config, stream, handler).await {
        Ok(running) => {
            if let Err(error) = running.await {
                tracing::debug!(%error, "fake Entware SSH connection ended");
            }
        }
        Err(error) => tracing::debug!(%error, "fake Entware SSH handshake failed"),
    }
}

/// What the fake does with one exec request.
enum Step {
    /// Drop the connection.
    Kill,
    /// Accept and never answer.
    Hang,
    /// Send `reply`, with an exit status when `exit_status` holds.
    Answer {
        /// Output and exit status.
        reply: Reply,
        /// Whether the exit status is sent.
        exit_status: bool,
    },
}

/// Counts and runs one command under the active fault switch.
fn execute(state: &mut State, text: &str) -> Step {
    state.counters.commands = state.counters.commands.saturating_add(1);
    match state.fault {
        Some(Fault::Hang) => Step::Hang,
        Some(Fault::KillAfter(limit)) if state.counters.commands > limit => Step::Kill,
        Some(Fault::HugeOutput) => {
            let mut reply = state.system.run(command::parse(text));
            reply
                .stdout
                .push_str(&HUGE_OUTPUT_LINE.repeat(HUGE_OUTPUT_LINES));
            Step::Answer {
                reply,
                exit_status: true,
            }
        }
        Some(Fault::NoExitStatus) => Step::Answer {
            reply: state.system.run(command::parse(text)),
            exit_status: false,
        },
        Some(Fault::KillAfter(_)) | None => Step::Answer {
            reply: state.system.run(command::parse(text)),
            exit_status: true,
        },
    }
}

/// Whether the `authorized_keys` text lists `offered`.
fn authorized(keys: &str, offered: &PublicKey) -> bool {
    keys.lines()
        .filter_map(|line| PublicKey::from_openssh(line.trim()).ok())
        .any(|listed| listed.key_data() == offered.key_data())
}

/// Sends `reply` on `channel`, then closes it; a client that left ends the delivery.
// cancel-safe: dropped, the rest of the reply is not sent; the command already ran.
async fn deliver(handle: server::Handle, channel: ChannelId, reply: Reply, exit_status: bool) {
    if !reply.stdout.is_empty()
        && handle
            .data(channel, reply.stdout.into_bytes())
            .await
            .is_err()
    {
        return;
    }
    if !reply.stderr.is_empty()
        && handle
            .extended_data(channel, 1, reply.stderr.into_bytes())
            .await
            .is_err()
    {
        return;
    }
    if exit_status
        && handle
            .exit_status_request(channel, reply.exit)
            .await
            .is_err()
    {
        return;
    }
    if handle.eof(channel).await.is_ok() && handle.close(channel).await.is_err() {
        tracing::debug!("fake Entware SSH client left before the channel closed");
    }
}

/// One connection's handler.
struct Connection {
    /// State shared with the fake.
    shared: Arc<Shared>,
}

impl server::Handler for Connection {
    type Error = russh::Error;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the russh handler trait"
    )]
    // cancel-safe: it has no await point.
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let matches = {
            let mut state = self.shared.lock();
            state.counters.auth_attempts = state.counters.auth_attempts.saturating_add(1);
            state.counters.password_attempts = state.counters.password_attempts.saturating_add(1);
            bool::from(password.as_bytes().ct_eq(state.password.as_bytes()))
        };
        Ok(if user == USER && matches {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the russh handler trait"
    )]
    // cancel-safe: it has no await point.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        let listed = {
            let mut state = self.shared.lock();
            state.counters.auth_attempts = state.counters.auth_attempts.saturating_add(1);
            state.counters.key_offers = state.counters.key_offers.saturating_add(1);
            authorized(&state.system.authorized_keys, offer.public_key)
        };
        Ok(if user == USER && listed {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the russh handler trait"
    )]
    // cancel-safe: it has no await point.
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let listed = authorized(&self.shared.lock().system.authorized_keys, key.public_key);
        Ok(if user == USER && listed {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    // cancel-safe: dropping the reply handle rejects the channel.
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the russh handler trait"
    )]
    // cancel-safe: it has no await point; the reply is delivered by its own task.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let text = String::from_utf8_lossy(data);
        let step = execute(&mut self.shared.lock(), &text);
        match step {
            Step::Kill => Err(russh::Error::Disconnect),
            Step::Hang => session.channel_success(channel),
            Step::Answer { reply, exit_status } => {
                session.channel_success(channel)?;
                drop(tokio::spawn(deliver(
                    session.handle(),
                    channel,
                    reply,
                    exit_status,
                )));
                Ok(())
            }
        }
    }
}
