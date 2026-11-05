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
    use core::error::Error;
    use std::{fs, path::Path};

    use kcc_app::{
        audit::{
            AUDIT_FILE_NAME, Actor, ActorKind, AuditError, AuditEvent, AuditLog, verify_chain,
        },
        persist::StateStore,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

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

    #[tokio::test]
    async fn rotation_preserves_chain_across_files() -> TestResult {
        let (_temp, state) = store()?;
        let audit = AuditLog::spawn_with_limit(&state, 1)?;

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
}
