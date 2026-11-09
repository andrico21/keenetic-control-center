//! Hash-chain, rotation, serialization and secret-rejection audit tests.

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{error::Error, fmt, time::Duration};
    use std::{fs, path::Path};

    use kcc_app::{
        accounts::Clock,
        audit::{
            AUDIT_FILE_NAME, Actor, ActorKind, AuditError, AuditEvent, AuditLog, AuditPolicy,
            verify_chain,
        },
        persist::StateStore,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    struct MockClock(u64);

    impl fmt::Debug for MockClock {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("MockClock").field(&self.0).finish()
        }
    }

    impl Clock for MockClock {
        fn unix_seconds(&self) -> u64 {
            self.0
        }
    }

    fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        Ok((temp, state))
    }

    fn event(sequence_hint: u64) -> AuditEvent {
        AuditEvent::new(
            1_700_000_000_u64.saturating_add(sequence_hint),
            Actor::new(ActorKind::Web, "alice".to_owned()),
            "router.read".to_owned(),
        )
        .with_params(json!({"section": "system"}))
        .with_result("ok".to_owned(), format!("request-{sequence_hint}"))
        .with_router("home".to_owned())
        .with_target("system".to_owned())
    }

    #[tokio::test]
    async fn concurrent_handles_serialize_into_one_valid_chain() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn(&state)?;
        let first = audit.clone();
        let second = audit.clone();

        let (one, two) = tokio::join!(first.append(event(1)), second.append(event(2)));
        let first_entry = one?;
        let second_entry = two?;
        drop(audit);

        let verified = verify_chain(state.dir())?;
        assert_eq!(verified.len(), 2, "both channel sends are durable");
        assert_ne!(
            first_entry.seq, second_entry.seq,
            "writer assigns unique sequences"
        );
        assert_eq!(
            verified.first().map(|entry| entry.seq),
            Some(1),
            "chain starts at one"
        );
        assert_eq!(
            verified.last().map(|entry| entry.seq),
            Some(2),
            "chain is contiguous"
        );
        Ok(())
    }

    #[tokio::test]
    async fn tampered_line_fails_at_its_exact_sequence() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn(&state)?;
        drop(audit.append(event(1)).await?);
        drop(audit.append(event(2)).await?);
        drop(audit.append(event(3)).await?);
        drop(audit);
        let path = state.dir().join(AUDIT_FILE_NAME);
        let raw = fs::read_to_string(&path)?;
        let mut lines: Vec<Value> = raw
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        let second = lines.get_mut(1).ok_or("second audit line missing")?;
        let object = second
            .as_object_mut()
            .ok_or("second audit line is not an object")?;
        drop(object.insert("outcome".to_owned(), Value::from("tampered")));
        let mut tampered = lines
            .into_iter()
            .map(|line| serde_json::to_string(&line))
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");
        tampered.push('\n');
        fs::write(&path, tampered)?;

        let result = verify_chain(state.dir());

        assert!(
            matches!(result, Err(AuditError::Chain { seq: 2 })),
            "tamper must be attributed to sequence 2, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn invalid_audit_error_omits_stored_value() -> TestResult {
        let (_temp, state) = store()?;
        let planted = format!("{}{}", "sensitive-", "value".repeat(12));
        fs::write(
            state.dir().join(AUDIT_FILE_NAME),
            format!(r#"{{"ts":"{planted}"}}"#),
        )?;

        let Err(error) = verify_chain(state.dir()) else {
            return Err("invalid timestamp unexpectedly verified".into());
        };
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(!display.contains(&planted), "Display omits stored values");
        assert!(!debug.contains(&planted), "Debug omits stored values");
        assert!(
            display.contains("line ") && display.contains("column "),
            "location remains actionable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rotation_preserves_chain_across_files() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn_with_policy(
            &state,
            AuditPolicy::default()
                .with_rotate_bytes(1)
                .with_retention(Duration::ZERO),
        )?;

        drop(audit.append(event(1)).await?);
        drop(audit.append(event(2)).await?);
        drop(audit);

        let names = fs::read_dir(state.dir())?
            .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        let verified = verify_chain(state.dir())?;
        assert!(
            names.iter().any(|name| name.starts_with("audit-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))),
            "a rotated archive exists: {names:?}"
        );
        assert_eq!(verified.len(), 2, "both files form one chain");
        assert_eq!(
            verified.last().map(|entry| entry.seq),
            Some(2),
            "sequence crosses rotation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rotation_prunes_entirely_expired_files_and_preserves_anchor() -> TestResult {
        let (_temp, state) = store()?;
        let now = 1_800_000_000_u64;
        let clock: Arc<dyn Clock> = Arc::new(MockClock(now));
        let policy = AuditPolicy::default()
            .with_rotate_bytes(1)
            .with_retention(Duration::from_secs(100))
            .with_clock(clock);
        let audit = AuditLog::spawn_with_policy(&state, policy)?;
        let mut expired = event(1);
        expired.ts = now.saturating_sub(101);
        let first = audit.append(expired).await?;
        let mut kept = event(2);
        kept.ts = now.saturating_sub(99);

        let second = audit.append(kept).await?;
        drop(audit);

        let names = fs::read_dir(state.dir())?
            .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            !names
                .iter()
                .any(|name| name == "audit-00000000000000000001.jsonl"),
            "the archive whose newest entry expired is pruned: {names:?}"
        );
        let verified = verify_chain(state.dir())?;
        assert_eq!(verified, vec![second], "the retained suffix verifies");
        assert_eq!(
            verified.first().map(|entry| entry.prev_hash.as_str()),
            Some(first.hash.as_str()),
            "the first retained entry reports the deleted prefix hash as its anchor"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rotation_prunes_only_expired_prefix_when_timestamps_are_out_of_order() -> TestResult {
        let (_temp, state) = store()?;
        let now = 1_800_000_000_u64;
        let rotation_only = AuditPolicy::default()
            .with_rotate_bytes(1)
            .with_retention(Duration::ZERO);
        let audit = AuditLog::spawn_with_policy(&state, rotation_only)?;
        let mut first_expired = event(1);
        first_expired.ts = now.saturating_sub(101);
        drop(audit.append(first_expired).await?);
        let mut middle_kept = event(2);
        middle_kept.ts = now.saturating_sub(99);
        let middle = audit.append(middle_kept).await?;
        let mut last_expired = event(3);
        last_expired.ts = now.saturating_sub(101);
        let last = audit.append(last_expired).await?;
        drop(audit);

        let clock: Arc<dyn Clock> = Arc::new(MockClock(now));
        let retention = AuditPolicy::default()
            .with_rotate_bytes(1)
            .with_retention(Duration::from_secs(100))
            .with_clock(clock);
        let pruning_audit = AuditLog::spawn_with_policy(&state, retention.clone())?;
        drop(pruning_audit.append(event(4)).await?);
        drop(pruning_audit);

        let names = fs::read_dir(state.dir())?
            .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            !names
                .iter()
                .any(|name| name == "audit-00000000000000000001.jsonl"),
            "the expired prefix is pruned: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name == "audit-00000000000000000002.jsonl"),
            "the first unexpired archive remains: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name == "audit-00000000000000000003.jsonl"),
            "later expired archives remain contiguous with the retained chain: {names:?}"
        );
        let verified = verify_chain(state.dir())?;
        assert_eq!(
            verified.first().map(|entry| entry.seq),
            Some(middle.seq),
            "the retained chain starts at the first unexpired archive"
        );
        assert!(
            verified.iter().any(|entry| entry.seq == last.seq),
            "the retained chain includes the later expired archive"
        );
        drop(AuditLog::spawn_with_policy(&state, retention)?);
        Ok(())
    }

    #[tokio::test]
    async fn secret_shaped_parameters_are_rejected_before_write() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn(&state)?;
        let mut secret_event = event(1);
        secret_event.params_redacted = json!({"password": "never-write-this"});

        let result = audit.append(secret_event).await;

        assert!(
            matches!(result, Err(AuditError::SecretParameter { key }) if key == "password"),
            "secret key rejected without serializing its value"
        );
        assert_eq!(
            fs::read_to_string(state.dir().join(AUDIT_FILE_NAME))?,
            "",
            "rejected event leaves audit log empty"
        );
        Ok(())
    }

    #[tokio::test]
    async fn liveness_turns_false_after_writer_failure() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn_with_limit(&state, 1)?;
        drop(audit.append(event(1)).await?);
        fs::create_dir_all(state.dir().join("audit-00000000000000000001.jsonl"))?;

        let result = audit.append(event(2)).await;

        assert!(
            result.is_err(),
            "forced rotation failure reaches the caller"
        );
        assert!(!audit.is_alive(), "terminated writer is not ready");
        Ok(())
    }
}
