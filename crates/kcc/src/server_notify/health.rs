//! Whether a router is reachable, judged from its poll results alone.
//!
//! A router is offline after two failed polls in a row and online again at the first
//! answer after that; a streak of refused logins is one message. A refused login proves
//! the router answers, so it never counts towards offline.

use core::mem;

/// What one poll result says about the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Poll {
    /// The router answered.
    Answered,
    /// The router refused kcc's login.
    LoginRefused,
    /// Any other failure.
    Failed,
}

/// A change worth a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Transition {
    /// Offline since the first of the failed polls, in Unix seconds.
    Down {
        /// When the first failed poll was seen.
        since: u64,
    },
    /// Online again after this many seconds offline.
    Up {
        /// Seconds from the first failed poll to the answer.
        outage: u64,
    },
    /// The first refused login of a streak.
    LoginRefused,
}

/// What is known about the router's reachability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Reach {
    /// Nothing decided yet.
    #[default]
    Unknown,
    /// It answers.
    Up,
    /// It is offline.
    Down {
        /// When the first failed poll was seen.
        since: u64,
        /// Whether the offline message was sent (it is held back while muted).
        announced: bool,
    },
}

/// The reachability of one router.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RouterTracker {
    /// What is known.
    reach: Reach,
    /// Failed polls in a row, refused logins excluded.
    failures: u8,
    /// When the first of those failed polls was seen.
    first_failure: Option<u64>,
    /// Whether the current streak of refused logins was already reported.
    login_reported: bool,
}

impl RouterTracker {
    /// Takes one poll result seen at `at` (Unix seconds). While `muted`, a change of
    /// reachability is tracked but not reported: an offline router whose mute ended is
    /// reported at its next failed poll, and its return is reported only when its going
    /// offline was.
    pub(super) fn observe(&mut self, poll: Poll, at: u64, muted: bool) -> Option<Transition> {
        match poll {
            Poll::Answered => {
                self.failures = 0;
                self.first_failure = None;
                self.login_reported = false;
                match mem::replace(&mut self.reach, Reach::Up) {
                    Reach::Down {
                        since,
                        announced: true,
                    } if !muted => Some(Transition::Up {
                        outage: at.saturating_sub(since),
                    }),
                    Reach::Down {
                        since: _,
                        announced: _,
                    }
                    | Reach::Unknown
                    | Reach::Up => None,
                }
            }
            Poll::LoginRefused => {
                self.failures = 0;
                self.first_failure = None;
                if self.login_reported {
                    return None;
                }
                self.login_reported = true;
                Some(Transition::LoginRefused)
            }
            Poll::Failed => {
                self.login_reported = false;
                let first = *self.first_failure.get_or_insert(at);
                self.failures = self.failures.saturating_add(1);
                self.failed(first, muted)
            }
        }
    }

    /// The transition after a failed poll whose streak began at `first`.
    fn failed(&mut self, first: u64, muted: bool) -> Option<Transition> {
        let since = match self.reach {
            Reach::Down {
                since,
                announced: false,
            } => since,
            Reach::Unknown | Reach::Up if self.failures >= 2 => first,
            Reach::Down {
                since: _,
                announced: true,
            }
            | Reach::Unknown
            | Reach::Up => return None,
        };
        self.reach = Reach::Down {
            since,
            announced: !muted,
        };
        (!muted).then_some(Transition::Down { since })
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{Poll, RouterTracker, Transition};

    /// Feeds `polls` (result, Unix seconds, muted) and collects every transition.
    fn run(tracker: &mut RouterTracker, polls: &[(Poll, u64, bool)]) -> Vec<Transition> {
        polls
            .iter()
            .filter_map(|&(poll, at, muted)| tracker.observe(poll, at, muted))
            .collect()
    }

    /// Todo 10: two failed polls in a row report one offline message naming the first
    /// failure; later failures report nothing more.
    #[test]
    fn two_failures_report_one_down_from_the_first_failure() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Answered, 100, false),
                (Poll::Failed, 115, false),
                (Poll::Failed, 235, false),
                (Poll::Failed, 355, false),
            ],
        );
        assert_eq!(seen, [Transition::Down { since: 115 }], "one down");
    }

    /// Todo 10: the first answer after offline reports one return with the outage
    /// length; a single failure between answers reports nothing.
    #[test]
    fn the_first_answer_after_down_reports_one_up() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Answered, 0, false),
                (Poll::Failed, 10, false),
                (Poll::Answered, 20, false),
                (Poll::Failed, 30, false),
                (Poll::Failed, 150, false),
                (Poll::Answered, 400, false),
                (Poll::Answered, 415, false),
            ],
        );
        assert_eq!(
            seen,
            [
                Transition::Down { since: 30 },
                Transition::Up { outage: 370 }
            ],
            "one down, one up"
        );
    }

    /// Todo 10: a router already failing when kcc starts gets one offline message.
    #[test]
    fn a_router_failing_at_start_reports_one_down() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Failed, 5, false),
                (Poll::Failed, 125, false),
                (Poll::Failed, 245, false),
            ],
        );
        assert_eq!(seen, [Transition::Down { since: 5 }], "one down");
    }

    /// Todo 10: a streak of refused logins reports once, never counts as offline, and
    /// a new streak after an answer reports again.
    #[test]
    fn a_login_streak_reports_once() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Answered, 0, false),
                (Poll::LoginRefused, 15, false),
                (Poll::LoginRefused, 135, false),
                (Poll::LoginRefused, 255, false),
                (Poll::Answered, 375, false),
                (Poll::LoginRefused, 390, false),
            ],
        );
        assert_eq!(
            seen,
            [Transition::LoginRefused, Transition::LoginRefused],
            "one line per streak, no down"
        );
    }

    /// Todo 10: while muted, going offline and coming back are tracked but not reported.
    #[test]
    fn a_mute_suppresses_down_and_up() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Answered, 0, false),
                (Poll::Failed, 15, true),
                (Poll::Failed, 135, true),
                (Poll::Answered, 255, true),
                (Poll::Answered, 270, false),
            ],
        );
        assert_eq!(seen, [], "nothing while muted");
    }

    /// Todo 10: a router still offline when its mute ends is reported at the next failed
    /// poll, and its return after that is reported too.
    #[test]
    fn a_router_still_down_after_the_mute_is_reported() {
        let mut tracker = RouterTracker::default();
        let seen = run(
            &mut tracker,
            &[
                (Poll::Answered, 0, false),
                (Poll::Failed, 15, true),
                (Poll::Failed, 135, true),
                (Poll::Failed, 1000, false),
                (Poll::Answered, 1100, false),
            ],
        );
        assert_eq!(
            seen,
            [
                Transition::Down { since: 15 },
                Transition::Up { outage: 1085 }
            ],
            "down once the mute ended, then up"
        );
    }
}
