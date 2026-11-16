//! Sign-ins under concurrency.
//!
//! The password check runs outside the `users.json` lock, at most one Argon2 run per
//! available CPU at a time, and the file is written only when an account's failure count
//! or lockout changes.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]

mod harness;

extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;

use self::harness::{
    Answer, Fixture, Observed, TestResult, WAIT, file, on_thread, password, slots, turn,
};
use super::{AccountChange, Authentication, NewAccount, hashing::probe::Work};
use crate::permissions::{Permission, Role};

/// B-05, SEC1-11: sign-ins of two accounts check passwords at the same time.
///
/// One sign-in held inside its Argon2 run does not hold up the other, which records its
/// failure meanwhile.
#[test]
fn a_held_password_check_does_not_hold_up_another_account() -> TestResult {
    let _turn = turn();
    let _slots = slots()?;
    let fixture = Fixture::new(5, &["alice", "bob"])?;
    let held = Observed::new(Some(Work::Verify));
    let alice = fixture.sign_in(&held, ("alice", "wrong"));
    let running = held.until("alice's check runs", |board| board.running() == 1);
    let bob = fixture
        .sign_in(&Observed::new(None), ("bob", "wrong"))
        .recv_timeout(WAIT);
    held.release();

    running?;
    assert_eq!(
        bob.map_err(|_timeout| "bob waited for alice")?,
        Ok(Authentication::Invalid),
        "bob"
    );
    assert_eq!(
        alice.recv_timeout(WAIT)?,
        Ok(Authentication::Invalid),
        "alice"
    );
    assert_eq!(fixture.account("bob")?.failure_count, 1, "bob's failure");
    assert_eq!(
        fixture.account("alice")?.failure_count,
        1,
        "alice's failure"
    );
    Ok(())
}

/// B-05 (critic correction): at most one Argon2 run per available CPU at a time.
///
/// Of N+1 simultaneous sign-ins, N run their check and one waits for a free slot.
#[test]
fn simultaneous_sign_ins_run_at_most_one_check_per_cpu() -> TestResult {
    let _turn = turn();
    let slots = slots()?;
    let fixture = Fixture::new(5, &[])?;
    let held = Observed::new(Some(Work::Dummy));
    let answers: Vec<Answer> = (0..=slots)
        .map(|index| fixture.sign_in(&held, (&format!("ghost-{index}"), "any")))
        .collect();
    let full = held.until("every slot runs and one sign-in waits", |board| {
        board.running() == slots && board.waiting() == 1
    });
    let most = held.most();
    held.release();

    full?;
    assert_eq!(most, slots, "runs at once");
    for answer in answers {
        assert_eq!(
            answer.recv_timeout(WAIT)?,
            Ok(Authentication::Invalid),
            "unknown"
        );
    }
    Ok(())
}

/// B-05, SEC2-12: sign-ins that change no counter leave `users.json` untouched.
///
/// A refused unknown name and a sign-in with no failures to clear keep the same file
/// time, size and bytes.
#[test]
fn sign_ins_that_change_no_counter_leave_the_file_untouched() -> TestResult {
    let fixture = Fixture::new(5, &["alice"])?;
    let before = file(fixture.users())?;

    let unknown = fixture
        .sign_in(&Observed::new(None), ("nobody", "alice"))
        .recv_timeout(WAIT)?;
    let known = fixture
        .sign_in(&Observed::new(None), ("alice", "alice"))
        .recv_timeout(WAIT)?;

    assert_eq!(unknown, Ok(Authentication::Invalid), "unknown name");
    assert_eq!(
        known,
        Ok(Authentication::Authenticated {
            role: "viewer".to_owned(),
            locale: "en".to_owned(),
        }),
        "right password"
    );
    assert!(file(fixture.users())? == before, "users.json was rewritten");
    Ok(())
}

/// N4, SEC1-11, SEC2-12: disabled and locked accounts run the stand-in Argon2 check.
///
/// They do the same work as a wrong password, so their answer takes as long.
#[test]
fn disabled_and_locked_accounts_run_the_stand_in_check() -> TestResult {
    let fixture = Fixture::new(1, &["alice", "bob"])?;
    let _before = fixture
        .store()
        .administer("alice", &AccountChange::Disabled(true))?;
    let locking = fixture.store().authenticate("bob", &password("wrong"))?;
    assert!(
        matches!(locking, Authentication::Locked { until: _ }),
        "bob locks: {locking:?}"
    );
    let observed = Observed::new(None);

    let disabled = fixture
        .sign_in(&observed, ("alice", "alice"))
        .recv_timeout(WAIT)?;
    let locked = fixture
        .sign_in(&observed, ("bob", "bob"))
        .recv_timeout(WAIT)?;

    assert_eq!(disabled, Ok(Authentication::Disabled), "alice");
    assert!(
        matches!(locked, Ok(Authentication::Locked { until: _ })),
        "bob: {locked:?}"
    );
    assert_eq!(
        observed.runs(),
        [Work::Dummy, Work::Dummy],
        "one stand-in check each"
    );
    Ok(())
}

/// Signs in `count` times at once as `alice` with a wrong password, every check running
/// before any finishes.
fn wrong_at_once(
    fixture: &Fixture,
    count: usize,
) -> Result<Vec<Authentication>, Box<dyn Error + Send + Sync>> {
    let held = Observed::new(Some(Work::Verify));
    let mut answers = Vec::with_capacity(count);
    for _attempt in 0..count {
        answers.push(fixture.sign_in(&held, ("alice", "wrong")));
    }
    let together = held.until("every check runs", |board| board.running() == count);
    held.release();
    together?;
    answers
        .into_iter()
        .map(|answer| Ok(answer.recv_timeout(WAIT)??))
        .collect()
}

/// B-05: wrong passwords checked at the same time each count once.
///
/// The account locks at the same attempt as with one attempt after another: no update is
/// lost and no attempt slips past the lockout.
#[test]
fn simultaneous_wrong_passwords_each_count_once() -> TestResult {
    let _turn = turn();
    let count = slots()?.min(4);

    let open = Fixture::new(100, &["alice"])?;
    let answers = wrong_at_once(&open, count)?;
    assert!(
        answers
            .iter()
            .all(|answer| *answer == Authentication::Invalid),
        "{answers:?}"
    );
    assert_eq!(
        open.account("alice")?.failure_count,
        u32::try_from(count)?,
        "every failure"
    );

    let strict = Fixture::new(2, &["alice"])?;
    let strict_answers = wrong_at_once(&strict, count)?;
    let invalid = strict_answers
        .iter()
        .filter(|answer| **answer == Authentication::Invalid)
        .count();
    assert_eq!(
        invalid, 1,
        "only the first failure stays below the lockout: {strict_answers:?}"
    );
    let alice = strict.account("alice")?;
    assert_eq!(alice.failure_count, 2, "failures counted up to the lockout");
    assert!(alice.lockout_until.is_some(), "locked");
    Ok(())
}

/// B-05: an account disabled during a sign-in's password check stays disabled.
///
/// The sign-in answers as disabled and counts no failure.
#[test]
fn a_disable_during_a_password_check_is_kept() -> TestResult {
    let _turn = turn();
    let _slots = slots()?;
    let fixture = Fixture::new(5, &["alice"])?;
    let held = Observed::new(Some(Work::Verify));
    let attempt = fixture.sign_in(&held, ("alice", "wrong"));
    let running = held.until("the check runs", |board| board.running() == 1);
    let store = Arc::clone(fixture.store());
    let disabled = on_thread(move || {
        store
            .administer("alice", &AccountChange::Disabled(true))
            .map(|before| before.is_some())
            .map_err(|error| error.to_string())
    })
    .recv_timeout(WAIT);
    held.release();

    running?;
    assert_eq!(
        disabled.map_err(|_timeout| "the disable waited for the sign-in")?,
        Ok(true),
        "disabled"
    );
    assert_eq!(
        attempt.recv_timeout(WAIT)?,
        Ok(Authentication::Disabled),
        "answer"
    );
    let alice = fixture.account("alice")?;
    assert!(alice.disabled, "the disable was overwritten");
    assert_eq!(alice.failure_count, 0, "no failure counted");
    Ok(())
}

/// B-05: a password reset during a sign-in's password check keeps the new hash.
///
/// The sign-in is checked again against the new password and counts its failure on the
/// reset counters.
#[test]
fn a_reset_during_a_password_check_is_kept() -> TestResult {
    let _turn = turn();
    let _slots = slots()?;
    let fixture = Fixture::new(5, &["alice"])?;
    fixture.store().create(NewAccount::new(
        "root".to_owned(),
        password("root"),
        "admin".to_owned(),
    ))?;
    let admin = Role::new(
        "admin".to_owned(),
        [Permission::ManageUsers],
        vec!["*".to_owned()],
    );
    let held = Observed::new(Some(Work::Verify));
    let attempt = fixture.sign_in(&held, ("alice", "wrong"));
    let running = held.until("the check runs", |board| board.running() == 1);
    let store = Arc::clone(fixture.store());
    let reset = on_thread(move || {
        store
            .reset_password(("root", &admin), "alice", &password("fresh"))
            .map_err(|error| error.to_string())
    })
    .recv_timeout(WAIT);
    let after_reset = fixture.account("alice")?.password_hash;
    held.release();

    running?;
    assert_eq!(
        reset.map_err(|_timeout| "the reset waited for the sign-in")?,
        Ok(true),
        "reset"
    );
    assert_eq!(
        attempt.recv_timeout(WAIT)?,
        Ok(Authentication::Invalid),
        "answer"
    );
    let alice = fixture.account("alice")?;
    assert!(
        alice.password_hash == after_reset,
        "the new hash was overwritten"
    );
    assert!(
        alice.must_change_password,
        "the reset's flag was overwritten"
    );
    assert_eq!(
        alice.failure_count, 1,
        "the failure counts once, after the reset"
    );
    assert_eq!(
        held.runs(),
        [Work::Verify, Work::Verify],
        "checked again against the new hash"
    );
    Ok(())
}
