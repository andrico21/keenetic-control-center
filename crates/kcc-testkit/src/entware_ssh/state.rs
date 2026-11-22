//! Mutable state of a running fake, shared by its connections and its handle, and the
//! mutating commands [`Fault::HoldMutations`] holds back until the handle releases them.

use core::mem;
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use russh::{ChannelId, keys::PrivateKey, server};
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::{Counters, Fault, Reply, System, command::Command};

/// A command accepted and not answered yet.
pub(super) struct Held {
    /// The connection's handle.
    pub handle: server::Handle,
    /// The channel the command came on.
    pub channel: ChannelId,
    /// The command; it runs when released.
    pub command: Command,
}

/// Mutable state of a running fake.
pub(super) struct State {
    /// Current host key; a new connection uses the key current at accept time.
    pub host_key: PrivateKey,
    /// Accepted password.
    pub password: Zeroizing<String>,
    /// Packages, services and `authorized_keys`.
    pub system: System,
    /// Active fault switch.
    pub fault: Option<Fault>,
    /// Activity counters.
    pub counters: Counters,
    /// Commands held back, in arrival order.
    pub held: Vec<Held>,
}

/// State shared by the connections and the handle.
pub(super) struct Shared {
    /// Guarded state.
    state: Mutex<State>,
    /// Commands held since the fake started.
    held: watch::Sender<u64>,
}

impl Shared {
    /// Fresh state over `system`, without a fault.
    pub(super) fn new(host_key: PrivateKey, password: Zeroizing<String>, system: System) -> Self {
        Self {
            state: Mutex::new(State {
                host_key,
                password,
                system,
                fault: None,
                counters: Counters::default(),
                held: Vec::new(),
            }),
            held: watch::Sender::new(0),
        }
    }

    /// Locks the state; a poisoned lock still holds consistent data.
    pub(super) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds `held` back until [`Self::release`].
    pub(super) fn hold(&self, held: Held) {
        self.lock().held.push(held);
        self.held
            .send_modify(|count| *count = count.saturating_add(1));
    }

    /// Waits until `count` commands were held since the fake started.
    ///
    /// # Errors
    /// None while `self` lives: the sender is part of it.
    // cancel-safe: it only waits.
    pub(super) async fn held(&self, count: u64) -> io::Result<()> {
        let mut seen = self.held.subscribe();
        seen.wait_for(|total| *total >= count)
            .await
            .map(drop)
            .map_err(io::Error::other)
    }

    /// Runs every held command, in arrival order, and returns where each reply goes.
    pub(super) fn release(&self) -> Vec<(server::Handle, ChannelId, Reply)> {
        let mut state = self.lock();
        let commands = mem::take(&mut state.held);
        let replies = commands
            .into_iter()
            .map(|command| {
                (
                    command.handle,
                    command.channel,
                    state.system.run(command.command),
                )
            })
            .collect();
        drop(state);
        replies
    }
}

/// Whether `command` changes the userland: what [`Fault::HoldMutations`] holds back.
pub(super) fn mutating(command: &Command) -> bool {
    match command {
        Command::ListInstalled
        | Command::ListUpgradable
        | Command::ListServices
        | Command::NotFound(_) => false,
        Command::Service { name: _, action } => action != "check",
        Command::Update
        | Command::Install(_)
        | Command::Remove(_)
        | Command::Upgrade(_)
        | Command::AppendKey {
            line: _,
            router_id: _,
        }
        | Command::RemoveKey { router_id: _ } => true,
    }
}
