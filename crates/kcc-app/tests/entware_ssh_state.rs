//! Sealed SSH enrolment records, private keys and their removal (todo 8).
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use fallible filesystem fixtures and assertions"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{fs, path::PathBuf};

use chacha20poly1305::aead::Generate as _;
use kcc_app::{
    accounts::Clock,
    entware_ssh::{
        SshStateError,
        state::{EnrolmentState, SshEnrolment, SshStore, active, forget},
        ticket::{TicketScope, TicketStore},
    },
    persist::StateStore,
    secrets::MasterKey,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tempfile::TempDir;

#[path = "entware_ssh_state/tickets.rs"]
mod tickets;

type TestResult = Result<(), Box<dyn Error>>;

/// A hand-moved clock in Unix seconds.
#[derive(Debug)]
struct HandClock(AtomicU64);

impl Clock for HandClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// One state directory, one master key, a store and a ticket store on a hand clock.
struct World {
    /// Keeps the directory alive.
    _temp: TempDir,
    /// The state root.
    state: StateStore,
    /// The master key's bytes.
    key: [u8; 32],
    /// Records and keys.
    store: SshStore,
    /// Tickets.
    tickets: TicketStore,
    /// The tickets' clock.
    clock: Arc<HandClock>,
}

impl World {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let key = <[u8; 32]>::try_generate().map_err(|error| error.to_string())?;
        let clock = Arc::new(HandClock(AtomicU64::new(1_800_000_000)));
        Ok(Self {
            store: SshStore::new(state.clone(), MasterKey::from_bytes(key)),
            tickets: TicketStore::new(
                state.clone(),
                MasterKey::from_bytes(key),
                Arc::<HandClock>::clone(&clock),
            ),
            _temp: temp,
            state,
            key,
            clock,
        })
    }

    /// Another ticket store over the same files, as a second process would open them.
    fn second_tickets(&self) -> TicketStore {
        TicketStore::new(
            self.state.clone(),
            MasterKey::from_bytes(self.key),
            Arc::<HandClock>::clone(&self.clock),
        )
    }

    /// `router-ssh/<name>`.
    fn file(&self, name: &str) -> PathBuf {
        self.state.dir().join("router-ssh").join(name)
    }

    /// The names in `router-ssh/`, sorted.
    fn names(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = fs::read_dir(self.state.dir().join("router-ssh"))?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        names.sort_unstable();
        Ok(names)
    }
}

/// A dummy private key text built at run time.
fn dummy_key() -> Result<SecretString, Box<dyn Error>> {
    let bytes = <[u8; 16]>::try_generate().map_err(|error| error.to_string())?;
    Ok(SecretString::from(format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{bytes:02x?}\n-----END OPENSSH PRIVATE KEY-----\n"
    )))
}

/// An active enrolment with a pin.
fn enrolled() -> SshEnrolment {
    let mut record = SshEnrolment::default();
    record.state = EnrolmentState::Active;
    record.port = 2222;
    record.router_host = Some("router.example".to_owned());
    record.host_key = Some(format!("ssh-ed25519 {}", "A".repeat(68)));
    record.fingerprint = Some(format!("SHA256:{}", "b".repeat(43)));
    record.enrolled_at = Some(1_800_000_000);
    record.enrolled_by = Some("admin".to_owned());
    record
}

/// Todo 8: a record and a key come back as saved; nothing is stored for another router.
#[test]
fn record_and_key_round_trip() -> TestResult {
    let world = World::new()?;
    let key = dummy_key()?;

    world.store.save("a", &enrolled())?;
    world.store.save_key("a", &key)?;

    assert_eq!(world.store.load("a")?, Some(enrolled()));
    assert_eq!(
        world
            .store
            .load_key("a")?
            .map(|opened| opened.expose_secret().to_owned()),
        Some(key.expose_secret().to_owned())
    );
    assert_eq!(world.store.load("b")?, None);
    assert!(world.store.load_key("b")?.is_none());
    assert_eq!(world.names()?, ["a.key.sealed", "a.sealed"]);
    let on_disk = fs::read_to_string(world.file("a.key.sealed"))?;
    assert!(!on_disk.contains(key.expose_secret()), "the key is sealed");
    assert!(!on_disk.contains("OPENSSH"), "no plaintext on disk");
    Ok(())
}

/// Todo 8: a record is bound to its router and part: copied to another router, to the key
/// or to the ticket of the same router, it does not open.
#[test]
fn a_record_opens_only_as_itself() -> TestResult {
    let world = World::new()?;
    world.store.save("a", &enrolled())?;
    let sealed = fs::read(world.file("a.sealed"))?;

    fs::write(world.file("b.sealed"), &sealed)?;
    fs::write(world.file("a.key.sealed"), &sealed)?;
    fs::write(world.file("a.ticket.sealed"), &sealed)?;

    assert!(matches!(
        world.store.load("b"),
        Err(SshStateError::Crypto(_))
    ));
    assert!(matches!(
        world.store.load_key("a"),
        Err(SshStateError::Crypto(_))
    ));
    let redeemed = world
        .tickets
        .redeem(TicketScope::new("a", 222, "admin"), "00", "SHA256:x");
    assert!(
        matches!(redeemed, Err(SshStateError::Crypto(_))),
        "{redeemed:?}"
    );
    Ok(())
}

/// Todo 8: a record sealed under another master key, a damaged file and another schema
/// are errors, never a panic or a default record.
#[test]
fn foreign_damaged_or_other_schema_records_are_refused() -> TestResult {
    let world = World::new()?;
    world.store.save("a", &enrolled())?;
    let other = SshStore::new(world.state.clone(), MasterKey::from_bytes([7_u8; 32]));
    assert!(matches!(other.load("a"), Err(SshStateError::Crypto(_))));

    let text = fs::read_to_string(world.file("a.sealed"))?;
    let mut envelope: Value = serde_json::from_str(&text)?;
    *envelope.get_mut("schema").ok_or("schema")? = Value::from(2_u32);
    fs::write(world.file("a.sealed"), serde_json::to_vec(&envelope)?)?;
    assert!(matches!(world.store.load("a"), Err(SshStateError::Record)));

    let cut = text.get(..20).ok_or("cut")?;
    fs::write(world.file("a.sealed"), cut)?;
    assert!(matches!(world.store.load("a"), Err(SshStateError::Record)));
    fs::write(world.file("a.key.sealed"), cut)?;
    assert!(matches!(
        world.store.load_key("a"),
        Err(SshStateError::Record)
    ));
    assert!(matches!(
        world.store.load("A/.."),
        Err(SshStateError::InvalidRouter)
    ));
    Ok(())
}

/// Todo 8: `set_port` and `set_enabled` create a pending record on port 222 when absent and
/// keep the pin and the state of an existing one.
#[test]
fn port_and_switch_create_a_default_record_and_keep_the_pin() -> TestResult {
    let world = World::new()?;

    let created = world.store.set_enabled("a", false)?;
    let mut expected = SshEnrolment::default();
    expected.enabled = false;
    assert_eq!(created, expected);
    assert_eq!(expected.port, 222);
    assert_eq!(expected.state, EnrolmentState::Pending);
    assert_eq!(world.store.set_port("b", 2022)?.port, 2022);
    assert_eq!(
        world.store.load("b")?.map(|record| record.enabled),
        Some(true)
    );

    world.store.save("c", &enrolled())?;
    drop(world.store.set_port("c", 22)?);
    drop(world.store.set_enabled("c", false)?);
    let mut kept = enrolled();
    kept.port = 22;
    kept.enabled = false;
    assert_eq!(world.store.load("c")?, Some(kept));
    assert!(matches!(
        world.store.set_port("c", 0),
        Err(SshStateError::InvalidPort)
    ));
    Ok(())
}

/// Todo 8: `active` is true only for an active record, and for a record it cannot open.
#[test]
fn active_reads_the_state() -> TestResult {
    let world = World::new()?;
    assert!(!active(&world.store, "a"), "no record");
    drop(world.store.set_port("a", 222)?);
    assert!(!active(&world.store, "a"), "pending");
    world.store.save("a", &enrolled())?;
    assert!(active(&world.store, "a"), "active");
    fs::write(world.file("a.sealed"), "{")?;
    assert!(active(&world.store, "a"), "unreadable counts as active");
    Ok(())
}

/// Todo 8: `forget` removes exactly the record, key, ticket and redeeming tickets of `a`;
/// router `ab` keeps every file.
#[test]
fn forget_removes_exactly_the_routers_files() -> TestResult {
    let world = World::new()?;
    for router in ["a", "ab"] {
        world.store.save(router, &enrolled())?;
        world.store.save_key(router, &dummy_key()?)?;
        drop(world.tickets.issue(
            TicketScope::new(router, 222, "admin"),
            "ssh-ed25519 x",
            "SHA256:x",
        )?);
        fs::write(world.file(&format!("{router}.ticket.redeem.0f")), "x")?;
    }

    forget(&world.state, "a")?;
    forget(&world.state, "a")?;

    assert_eq!(
        world.names()?,
        [
            "ab.key.sealed",
            "ab.sealed",
            "ab.ticket.redeem.0f",
            "ab.ticket.sealed"
        ]
    );
    assert!(active(&world.store, "ab"));
    assert!(!active(&world.store, "a"));
    Ok(())
}

/// Todo 8: the directory is owner-only, and so are the key, record and ticket files.
#[cfg(unix)]
#[test]
fn files_are_owner_only() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let world = World::new()?;
    world.store.save("a", &enrolled())?;
    world.store.save_key("a", &dummy_key()?)?;
    drop(world.tickets.issue(
        TicketScope::new("a", 222, "admin"),
        "ssh-ed25519 x",
        "SHA256:x",
    )?);

    let mode = |path: PathBuf| -> Result<u32, Box<dyn Error>> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    };
    assert_eq!(mode(world.state.dir().join("router-ssh"))?, 0o700);
    for name in ["a.sealed", "a.key.sealed", "a.ticket.sealed"] {
        assert_eq!(mode(world.file(name))?, 0o600, "{name}");
    }
    Ok(())
}
