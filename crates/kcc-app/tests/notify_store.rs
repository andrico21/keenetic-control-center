//! Telegram notification settings, the notifier's delivery state and the sealed bot token.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use fallible filesystem fixtures and assertions"
)]

extern crate alloc;

use alloc::collections::BTreeSet;
use core::error::Error;
use std::fs;

use kcc_app::{
    notify_store::{
        NotifyError, NotifyEvent, NotifySettings,
        recipients::{Chat, ChatId, ChatLabel, Chats, MAX_CHATS},
    },
    persist::{StateError, StateStore},
    secrets::MasterKey,
};
use kcc_i18n::locale::Locale;
use serde_json::{Value, json};
use tempfile::TempDir;

#[path = "notify_store/token.rs"]
mod token;

type TestResult = Result<(), Box<dyn Error>>;

/// A state directory and a master key.
struct Fixture {
    /// Keeps the state directory alive.
    _temp: TempDir,
    /// The state root.
    state: StateStore,
    /// The master key.
    key: MasterKey,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        Ok(Self {
            _temp: temp,
            state,
            key: MasterKey::generate()?,
        })
    }
}

/// A chat with id `id` and label `label`.
fn chat(id: &str, label: &str) -> Result<Chat, NotifyError> {
    Ok(Chat::new(ChatId::parse(id)?, ChatLabel::parse(label)?))
}

/// Writes `document` as `notify.json` and reads it back as settings.
fn read_raw(fixture: &Fixture, document: &Value) -> Result<Option<NotifySettings>, StateError> {
    let path = fixture.state.dir().join("notify.json");
    fs::write(&path, document.to_string()).map_err(|source| StateError::Io { path, source })?;
    fixture.state.read::<NotifySettings>()
}

/// todo 5: the adopted default event set, notifications off, no client details.
#[test]
fn settings_default_to_off_with_the_adopted_events() {
    let settings = NotifySettings::default();
    let expected: BTreeSet<NotifyEvent> = [
        NotifyEvent::RouterDownUp,
        NotifyEvent::RouterLogin,
        NotifyEvent::ChangeFailed,
        NotifyEvent::ScheduledProblem,
        NotifyEvent::AccountLocked,
        NotifyEvent::AuditProblem,
        NotifyEvent::FirmwareUpdate,
        NotifyEvent::JobFailed,
    ]
    .into_iter()
    .collect();
    assert!(!settings.enabled);
    assert!(!settings.include_client_details);
    assert_eq!(settings.locale, None);
    assert_eq!(settings.events, expected);
    assert_eq!(settings.chats, Chats::default());
}

/// todo 5: `notify.json` keeps every field through a write and a read.
#[test]
fn settings_round_trip_through_notify_json() -> TestResult {
    let fixture = Fixture::new()?;
    let mut settings = NotifySettings::default();
    settings.enabled = true;
    settings.locale = Some(Locale::Ru);
    settings.include_client_details = true;
    settings.events = [NotifyEvent::NewDevice, NotifyEvent::ScheduledSuccess]
        .into_iter()
        .collect();
    let mut group = chat("-1001234567890", "Family")?;
    group.thread = Some(7);
    group.silent = true;
    settings.chats = Chats::new(vec![group, chat("@home_alerts", "Channel")?])?;
    fixture.state.write(&settings)?;

    let raw: Value = serde_json::from_slice(&fs::read(fixture.state.dir().join("notify.json"))?)?;
    assert_eq!(raw.get("schema"), Some(&json!(1_u32)));
    assert_eq!(raw.get("locale"), Some(&json!("ru")));
    assert_eq!(
        raw.get("events"),
        Some(&json!(["scheduled_success", "new_device"]))
    );
    assert_eq!(fixture.state.read::<NotifySettings>()?, Some(settings));
    Ok(())
}

/// todo 5: an unknown field, a bad chat id or label, an unsupported locale and an 11th
/// chat are refused when `notify.json` is read.
#[test]
fn notify_json_refuses_unknown_fields_and_invalid_values() -> TestResult {
    let fixture = Fixture::new()?;
    let good = json!({"id": "@home_alerts", "label": "Home"});
    assert!(read_raw(&fixture, &json!({"schema": 1_u32, "chats": [good]}))?.is_some());
    assert_eq!(
        read_raw(&fixture, &json!({"schema": 1_u32, "locale": "kk-KZ"}))?
            .and_then(|settings| settings.locale),
        Some(Locale::Kk)
    );

    let eleven: Vec<Value> = (1..=11_i64)
        .map(|id| json!({"id": id.to_string(), "label": "chat"}))
        .collect();
    let refused = [
        json!({"schema": 1_u32, "bogus": true}),
        json!({"schema": 1_u32, "chats": [{"id": "@home_alerts", "label": "Home", "bogus": 1_u8}]}),
        json!({"schema": 1_u32, "chats": [{"id": "0", "label": "Home"}]}),
        json!({"schema": 1_u32, "chats": [{"id": "@abcd", "label": "Home"}]}),
        json!({"schema": 1_u32, "chats": [{"id": "home_alerts", "label": "Home"}]}),
        json!({"schema": 1_u32, "chats": [{"id": "@home-alerts", "label": "Home"}]}),
        json!({"schema": 1_u32, "chats": [{"id": "@home_alerts", "label": ""}]}),
        json!({"schema": 1_u32, "locale": "xx"}),
        json!({"schema": 1_u32, "events": ["router_down"]}),
        json!({"schema": 1_u32, "chats": eleven}),
    ];
    for document in refused {
        let result = read_raw(&fixture, &document);
        assert!(
            matches!(result, Err(StateError::Corrupt { file: _, reason: _ })),
            "{document} gave {result:?}"
        );
    }
    Ok(())
}

/// todo 5: chat ids, labels and the chat list are checked when they are built.
#[test]
fn chat_values_are_checked_at_construction() -> TestResult {
    assert_eq!(
        ChatId::parse("-1001234567890")?.numeric(),
        Some(-1_001_234_567_890)
    );
    assert_eq!(ChatId::parse("@home_alerts")?.numeric(), None);
    assert_eq!(
        ChatId::parse(&format!("@{}", "a".repeat(32)))?
            .as_str()
            .len(),
        33
    );
    for bad in ["", "0", "-0", "1.5", "@abcd", "@", "@home alerts", "x123"] {
        assert!(
            matches!(
                ChatId::parse(bad),
                Err(NotifyError::Invalid { field: "chats.id" })
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        ChatId::parse(&format!("@{}", "a".repeat(33))),
        Err(NotifyError::Invalid { field: "chats.id" })
    ));
    assert_eq!(
        ChatLabel::parse(&"\u{e9}".repeat(64))?
            .as_str()
            .chars()
            .count(),
        64
    );
    for bad in [String::new(), "x".repeat(65), "two\nlines".to_owned()] {
        assert!(
            matches!(
                ChatLabel::parse(&bad),
                Err(NotifyError::Invalid {
                    field: "chats.label"
                })
            ),
            "{bad:?}"
        );
    }

    let chats = (1..=MAX_CHATS.saturating_add(1))
        .map(|id| chat(&id.to_string(), "chat"))
        .collect::<Result<Vec<_>, _>>()?;
    let (ten, _) = chats.split_at(MAX_CHATS);
    assert_eq!(Chats::new(ten.to_vec())?.as_slice().len(), MAX_CHATS);
    assert!(matches!(
        Chats::new(chats),
        Err(NotifyError::Invalid { field: "chats" })
    ));
    assert!(matches!(
        Chats::new(vec![chat("42", "a")?, chat("+42", "b")?]),
        Err(NotifyError::Invalid { field: "chats" })
    ));
    Ok(())
}
