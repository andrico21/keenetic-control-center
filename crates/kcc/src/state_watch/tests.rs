//! Follower reloads, driven by direct passes instead of poll ticks.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, io};

use tempfile::TempDir;

use super::{
    Trigger,
    follow::{Follower, Followers, observe_all},
};

/// Counts the reloads it is asked for.
#[derive(Debug, Default)]
struct Counting(AtomicUsize);

impl Follower for Counting {
    fn reload(&self) {
        let _previous = self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Counting {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

const ONE: &[&str] = &["one.json"];
const TWO: &[&str] = &["one.json", "two.json"];

/// A recorded watcher over `files` and the follower it reloads.
fn started(dir: &TempDir, files: &'static [&'static str]) -> (Followers, Arc<Counting>) {
    let follower = Arc::new(Counting::default());
    let mut followers = Followers::default();
    let handle: Arc<dyn Follower> = Arc::<Counting>::clone(&follower);
    followers.add(files, handle);
    pass(&mut followers, dir, Trigger::Start);
    (followers, follower)
}

/// One pass of `trigger` over the state directory.
fn pass(followers: &mut Followers, dir: &TempDir, trigger: Trigger) {
    followers.apply(trigger, observe_all(dir.path(), &followers.plan()));
}

/// todo 9: a changed file reloads its follower once.
#[test]
fn changed_file_reloads_once() -> io::Result<()> {
    let dir = TempDir::new()?;
    let (mut followers, follower) = started(&dir, ONE);
    assert_eq!(follower.count(), 0, "start only records");
    fs::write(dir.path().join("one.json"), "{}")?;
    pass(&mut followers, &dir, Trigger::Tick);
    assert_eq!(follower.count(), 1);
    Ok(())
}

/// todo 9: a pass that finds nothing changed reloads nothing.
#[test]
fn unchanged_pass_reloads_nothing() -> io::Result<()> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("one.json"), "{}")?;
    let (mut followers, follower) = started(&dir, ONE);
    pass(&mut followers, &dir, Trigger::Tick);
    pass(&mut followers, &dir, Trigger::Tick);
    assert_eq!(follower.count(), 0);
    Ok(())
}

/// todo 9: two files changed in one pass reload the follower once.
#[test]
fn two_changed_files_reload_once() -> io::Result<()> {
    let dir = TempDir::new()?;
    let (mut followers, follower) = started(&dir, TWO);
    fs::write(dir.path().join("one.json"), "{}")?;
    fs::write(dir.path().join("two.json"), "{}")?;
    pass(&mut followers, &dir, Trigger::Tick);
    assert_eq!(follower.count(), 1);
    Ok(())
}

/// todo 9: a removed file reloads the follower once, and only once.
#[test]
fn removed_file_reloads_once() -> io::Result<()> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("one.json"), "{}")?;
    let (mut followers, follower) = started(&dir, ONE);
    fs::remove_file(dir.path().join("one.json"))?;
    pass(&mut followers, &dir, Trigger::Tick);
    pass(&mut followers, &dir, Trigger::Tick);
    assert_eq!(follower.count(), 1);
    Ok(())
}

/// todo 9: SIGHUP reloads the follower once, changed or not.
#[cfg(unix)]
#[test]
fn hangup_reloads_once() -> io::Result<()> {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("one.json"), "{}")?;
    let (mut followers, follower) = started(&dir, TWO);
    pass(&mut followers, &dir, Trigger::Hangup);
    assert_eq!(follower.count(), 1);
    Ok(())
}
