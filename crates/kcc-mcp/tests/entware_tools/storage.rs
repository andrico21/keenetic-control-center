//! `kcc_storage_write` `eject` and `initialize` of the drive Entware runs from.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert refusals and the request log"
)]
mod tests {
    use serde_json::json;

    use crate::{
        helpers::{every, lab_on, lines, refused_quietly},
        lab::{TestResult, admin},
    };

    /// The storage write tool.
    const STORAGE: &str = "kcc_storage_write";

    /// Todo 14: the Entware drive is ejected or initialized only when acknowledged.
    ///
    /// Without `acknowledge_entware_drive` the call is refused with `conflict` and never
    /// sent; with it the router receives the line (the fake router refuses every eject).
    #[tokio::test]
    async fn the_entware_drive_needs_the_acknowledgement() -> TestResult {
        for (op, line, outcome) in [
            ("initialize", "media Media0 initialize ext4", None),
            ("eject", "system eject Media0", Some("router_rejected")),
        ] {
            let lab = lab_on(every(true), admin()).await?;
            assert!(lab.router("lab-1")?.configure("opkg disk fixture-media:/"));
            let call = json!({"host": "lab-1", "op": op, "name": "Media0", "confirm": true});

            let refused = lab.call(STORAGE, call.clone(), false).await?;
            assert_eq!(refused.error(), Some("conflict"), "{op}: {refused:?}");
            assert!(
                lines(&lab)?.iter().all(|sent| sent != line),
                "{op}: the router heard {line}"
            );

            let mut acknowledged = call;
            if let Some(object) = acknowledged.as_object_mut() {
                drop(object.insert("acknowledge_entware_drive".to_owned(), json!(true)));
            }
            let reply = lab.call(STORAGE, acknowledged, false).await?;
            assert_eq!(reply.error(), outcome, "{op}: {reply:?}");
            assert!(
                lines(&lab)?.iter().any(|sent| sent == line),
                "{op}: {line} was not sent"
            );
            lab.stop().await?;
        }
        Ok(())
    }

    /// Todo 14: `initialize` is destructive: refused without the server switch or without
    /// `confirm`, before the router is contacted.
    #[tokio::test]
    async fn initialize_needs_the_server_switch_and_confirmation() -> TestResult {
        let call = json!({"host": "lab-1", "op": "initialize", "name": "Media0"});
        let off = lab_on(every(false), admin()).await?;
        let mut confirmed = call.clone();
        if let Some(object) = confirmed.as_object_mut() {
            drop(object.insert("confirm".to_owned(), json!(true)));
        }
        refused_quietly(&off, (STORAGE, confirmed), "destructive_disabled").await?;
        off.stop().await?;
        let on = lab_on(every(true), admin()).await?;
        refused_quietly(&on, (STORAGE, call), "confirm_required").await?;
        on.stop().await
    }
}
