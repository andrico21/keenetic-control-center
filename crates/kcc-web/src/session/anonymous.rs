//! The bound on sessions before login: how many the store holds, how many one client
//! address holds, and how long one lasts unused.

use core::{net::IpAddr, time::Duration};
use std::collections::HashMap;

use super::{Session, SessionId};

/// Most sessions before login the store holds at once.
const MAX_ANONYMOUS: usize = 10_000;
/// Most sessions before login one client address holds at once.
const MAX_ANONYMOUS_PER_CLIENT: usize = 64;
/// Inactivity after which a session before login ends, unless the configured idle
/// timeout is shorter.
pub(super) const ANONYMOUS_IDLE: Duration = Duration::from_mins(5);

/// Where a session before login came from, and when it was admitted.
#[derive(Debug, Clone, Copy)]
pub(super) struct Admission {
    /// Client address the kit resolved; absent outside the kit's listener, where every
    /// such session shares one allowance.
    client: Option<IpAddr>,
    /// Position in the store's admission order; smaller is older.
    order: u64,
}

impl Admission {
    /// The `order`th session before login, opened from `client`.
    pub(super) const fn new(client: Option<IpAddr>, order: u64) -> Self {
        Self { client, order }
    }
}

/// Makes room for one more session before login from `client`.
///
/// Evicts the oldest session before login: from `client` when that address already
/// holds its 64, otherwise from anyone when the store already holds its 10 000.
/// Evicting rather than refusing keeps the login page working for everyone during a
/// flood; signed-in sessions are never evicted. Called with the table locked, before
/// every insertion, so neither cap is ever exceeded; one pass over the table.
pub(super) fn make_room(sessions: &mut HashMap<SessionId, Session>, client: Option<IpAddr>) {
    let mut total = 0_usize;
    let mut same = 0_usize;
    let mut oldest: Option<(u64, &SessionId)> = None;
    let mut oldest_same: Option<(u64, &SessionId)> = None;
    for (id, admission) in sessions
        .iter()
        .filter_map(|(id, session)| session.admission.map(|admission| (id, admission)))
    {
        total = total.saturating_add(1);
        if oldest.is_none_or(|(order, _id)| admission.order < order) {
            oldest = Some((admission.order, id));
        }
        if admission.client == client {
            same = same.saturating_add(1);
            if oldest_same.is_none_or(|(order, _id)| admission.order < order) {
                oldest_same = Some((admission.order, id));
            }
        }
    }
    let victim = if same >= MAX_ANONYMOUS_PER_CLIENT {
        oldest_same
    } else if total >= MAX_ANONYMOUS {
        oldest
    } else {
        None
    };
    if let Some(id) = victim.map(|(_order, id)| id.clone()) {
        drop(sessions.remove(&id));
    }
}
