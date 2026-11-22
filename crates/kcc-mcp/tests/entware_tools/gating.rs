//! The safety gates of `kcc_entware_write`: the server switch and confirmation of the
//! destructive operations, the management bracket of `dns_override`, and the boundary
//! checks of every free-text argument.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert refusals and the request log"
)]
mod tests {
    use kcc_testkit::{FakeRouter, bracket::Recovery, migration, model::Profile};
    use serde_json::{Value, json};

    use crate::{
        helpers::{every, lab_on, lab_with, lines, refused_quietly},
        lab::{TestResult, admin},
    };

    /// The write tool.
    const WRITE: &str = "kcc_entware_write";

    /// The destructive operations with their arguments, unconfirmed.
    fn destructive() -> [Value; 3] {
        [
            json!({"host": "lab-1", "op": "setup", "drive": "fixture-media:/"}),
            json!({"host": "lab-1", "op": "initrc", "initrc": "/opt/etc/init.d/rc.unslung"}),
            json!({"host": "lab-1", "op": "remove"}),
        ]
    }

    /// `arguments` with `confirm: true`.
    fn confirmed(mut arguments: Value) -> Value {
        if let Some(object) = arguments.as_object_mut() {
            drop(object.insert("confirm".to_owned(), json!(true)));
        }
        arguments
    }

    /// Todo 14: `setup`, `initrc` and `remove` are refused with `destructive_disabled`
    /// while `allow_destructive` is off, even confirmed, and the router hears nothing.
    #[tokio::test]
    async fn destructive_operations_need_the_server_switch() -> TestResult {
        let lab = lab_on(every(false), admin()).await?;
        for arguments in destructive() {
            refused_quietly(&lab, (WRITE, confirmed(arguments)), "destructive_disabled").await?;
        }
        lab.stop().await
    }

    /// Todo 14: with the switch on, `setup`, `initrc` and `remove` without `confirm` are
    /// refused with `confirm_required` and the router hears nothing.
    #[tokio::test]
    async fn destructive_operations_need_confirmation() -> TestResult {
        let lab = lab_on(every(true), admin()).await?;
        for arguments in destructive() {
            refused_quietly(&lab, (WRITE, arguments), "confirm_required").await?;
        }
        lab.stop().await
    }

    /// Todo 14: `dns_override` without `confirm` is refused before any request.
    ///
    /// Confirmed, it needs no server switch and runs inside the recovery bracket (arm
    /// first, the change, disarm last) on both recovery mechanisms, warning that the
    /// router's DNS stops.
    #[tokio::test]
    async fn dns_override_needs_confirmation_and_runs_inside_the_bracket() -> TestResult {
        for mode in ["router", "extender"] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let router = FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario);
            let lab = lab_with(router, every(false), admin()).await?;
            let change = json!({"host": "lab-1", "op": "dns_override", "enabled": true});
            refused_quietly(&lab, (WRITE, change.clone()), "confirm_required").await?;

            let before = lines(&lab)?.len();
            let reply = lab.call(WRITE, confirmed(change), false).await?;

            let sent = lines(&lab)?.split_off(before);
            let [arm, disarm] = Recovery::for_mode(mode).lines();
            assert_eq!(
                sent.first().map(String::as_str),
                Some(arm),
                "{mode}: {sent:?}"
            );
            assert_eq!(
                sent.last().map(String::as_str),
                Some(disarm),
                "{mode}: {sent:?}"
            );
            assert!(
                sent.iter().any(|line| line == "opkg dns-override"),
                "{mode}: {sent:?}"
            );
            let value = reply.value()?;
            assert_eq!(value.get("applied"), Some(&json!(true)), "{value}");
            assert_eq!(
                value.get("warnings"),
                Some(&json!(["dns_override_stops_router_dns"])),
                "{value}"
            );
            lab.stop().await?;
        }
        Ok(())
    }

    /// Todo 14: hostile arguments are refused as `invalid_arguments` before any router
    /// request.
    ///
    /// They are a drive, time zone or init script with a space, a newline, `;`, `../`, a
    /// URL or over its length, a drive with `$`, a backtick or a non-ASCII character, an
    /// empty init script, a time zone outside the planner's grammar, an `arch` outside its
    /// enum and an unknown property.
    #[tokio::test]
    async fn hostile_values_are_refused_before_any_request() -> TestResult {
        let long = "a".repeat(300);
        let drives = [
            "fixture media:/".to_owned(),
            "fixture\nmedia:/".to_owned(),
            "fixture;reboot:/".to_owned(),
            "../:/".to_owned(),
            "../etc".to_owned(),
            "fixture$media:/".to_owned(),
            "fixture`media`:/".to_owned(),
            "fixture\u{fc}media:/".to_owned(),
            format!("{long}:/"),
        ];
        let timezones = [
            "Europe/Berlin now".to_owned(),
            "Europe/Berlin\nsystem reboot".to_owned(),
            "Europe/Berlin;reboot".to_owned(),
            "../Europe".to_owned(),
            "https://evil.example/tz".to_owned(),
            "-x".to_owned(),
            "AUTO".to_owned(),
            long.clone(),
        ];
        let scripts = [
            "/opt/etc/init.d/rc unslung".to_owned(),
            "/opt/etc/init.d/rc.unslung\nsystem reboot".to_owned(),
            "/opt/etc/init.d/rc.unslung;reboot".to_owned(),
            "/opt/../etc/rc.local".to_owned(),
            "/opt/".to_owned(),
            format!("/opt/{long}"),
        ];
        let lab = lab_on(every(true), admin()).await?;
        for drive in drives {
            let call = json!({"host": "lab-1", "op": "setup", "drive": drive, "confirm": true});
            refused_quietly(&lab, (WRITE, call), "invalid_arguments").await?;
        }
        for timezone in timezones {
            let call = json!({"host": "lab-1", "op": "timezone", "timezone": timezone});
            refused_quietly(&lab, (WRITE, call), "invalid_arguments").await?;
        }
        for script in scripts {
            let call = json!({"host": "lab-1", "op": "initrc", "initrc": script, "confirm": true});
            refused_quietly(&lab, (WRITE, call), "invalid_arguments").await?;
        }
        for call in [
            json!({"host": "lab-1", "op": "setup", "drive": "internal", "arch": "x86", "confirm": true}),
            json!({"host": "lab-1", "op": "setup", "drive": "internal", "arch": "https://bin.entware.net/x", "confirm": true}),
            json!({"host": "lab-1", "op": "setup", "drive": "internal", "url": "https://evil.example/i.tar.gz", "confirm": true}),
        ] {
            refused_quietly(&lab, (WRITE, call), "invalid_arguments").await?;
        }
        let extra = json!({"host": "lab-1", "op": "status", "extra": 1_u8});
        refused_quietly(&lab, ("kcc_entware_read", extra), "invalid_arguments").await?;
        lab.stop().await
    }
}
