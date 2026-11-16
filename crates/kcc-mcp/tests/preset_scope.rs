//! Preset router scope over a real session: a capture never replaces a preset of another
//! scope, and a preset of another scope answers like a missing one.
extern crate alloc;

#[expect(
    dead_code,
    reason = "the shared MCP session support; this suite needs part of it"
)]
#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the preset scope contract"
)]
mod tests {
    use std::fs;

    use kcc_app::permissions::{Permission, Role};
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, Reply, TestResult, admin};

    /// `office-1` and `lab-src`, and a session of an administrator over every router.
    async fn start() -> TestResult<Lab> {
        let routers = vec![
            ("office-1", FakeRouter::builder(Profile::default()).build()?),
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
        ];
        Lab::start(routers, admin()).await
    }

    /// Captures `dns-secure` from `source` as `name`.
    async fn capture(lab: &Lab, source: &str, name: &str) -> TestResult<Reply> {
        lab.call(
            "kcc_preset_capture",
            json!({"source": source, "groups": ["dns-secure"], "name": name}),
            false,
        )
        .await
    }

    /// Narrows the session's role to the `lab-*` routers.
    fn narrow_to_lab(lab: &Lab) {
        lab.roles.replace(vec![Role::new(
            "admin".to_owned(),
            Permission::ALL,
            vec!["lab-*".to_owned()],
        )]);
    }

    /// The failure of `reply` without its per-call correlation id.
    fn failure(reply: &Reply) -> TestResult<Value> {
        let mut value = reply.failure().cloned().ok_or("the call succeeded")?;
        drop(
            value
                .as_object_mut()
                .ok_or("not an object")?
                .remove("request_id"),
        );
        Ok(value)
    }

    /// E-02, G-02: a `lab-*` key holding `Migrate` captures under the name of a preset
    /// sourced from `office-1`; the capture is refused and audited, and the stored record
    /// stays byte for byte.
    #[tokio::test]
    async fn a_lab_scoped_key_cannot_replace_an_office_preset() -> TestResult {
        let lab = start().await?;
        let stored = capture(&lab, "office-1", "Office").await?;
        assert_eq!(stored.value()?.get("id"), Some(&json!("office")));
        let path = lab.state_dir().join("presets/office.json");
        let before = fs::read(&path)?;
        narrow_to_lab(&lab);

        let replaced = capture(&lab, "lab-src", "Office").await?;

        assert_eq!(replaced.error(), Some("forbidden"), "{replaced:?}");
        assert_eq!(fs::read(&path)?, before);
        let outcomes = lab
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_preset_capture")
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>();
        assert_eq!(outcomes.last().map(String::as_str), Some("forbidden"));
        for _ in 0..2_u8 {
            let mine = capture(&lab, "lab-src", "Bench").await?;
            assert_eq!(mine.value()?.get("id"), Some(&json!("bench")), "{mine:?}");
        }
        lab.stop().await
    }

    /// E-02, G-02: reading, deleting and applying a preset of another scope answer exactly
    /// what a missing id answers, and the preset stays stored.
    #[tokio::test]
    async fn a_preset_of_another_scope_answers_like_a_missing_one() -> TestResult {
        let lab = start().await?;
        drop(capture(&lab, "office-1", "Office").await?.value()?.clone());
        let path = lab.state_dir().join("presets/office.json");
        let before = fs::read(&path)?;
        narrow_to_lab(&lab);

        for (tool, arguments) in [
            ("kcc_preset_list", json!({})),
            ("kcc_preset_delete", json!({})),
            (
                "kcc_preset_apply",
                json!({"host": "lab-src", "dry_run": true}),
            ),
        ] {
            let mut answers = Vec::new();
            for id in ["office", "absent"] {
                let mut sent = arguments.clone();
                let key = if tool == "kcc_preset_apply" {
                    "preset_id"
                } else {
                    "id"
                };
                drop(
                    sent.as_object_mut()
                        .ok_or("not an object")?
                        .insert(key.to_owned(), json!(id)),
                );
                answers.push(failure(&lab.call(tool, sent, false).await?)?);
            }
            assert_eq!(answers.first(), answers.get(1), "{tool}");
        }
        assert_eq!(fs::read(&path)?, before);
        lab.stop().await
    }
}
