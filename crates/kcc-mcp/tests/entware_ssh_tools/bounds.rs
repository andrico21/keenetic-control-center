//! Strings from the router's userland are bounded in length: an oversized version or log
//! message is cut and marked, so a page always holds an item and the cursor advances.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the results"
)]
mod tests {
    use kcc_testkit::{
        entware_install::record,
        entware_ssh::{Config, Service},
    };
    use serde_json::{Value, json};

    use crate::{
        rig::Rig,
        support::{PACKAGES, SERVICES, Setup, TestResult, admin, every},
    };

    /// Characters a version may keep.
    const VERSION_CHARS: usize = 128;

    /// Characters a log message may keep.
    const MESSAGE_CHARS: usize = 1024;

    /// The items of `member` of every page of `tool` called with `arguments`, following
    /// `next_cursor` for at most ten pages.
    async fn every_page(
        rig: &Rig,
        tool: &str,
        arguments: Value,
        member: &str,
    ) -> TestResult<Vec<Value>> {
        let (mut items, mut cursor) = (Vec::new(), None::<String>);
        for _page in 0_u8..10 {
            let mut page_arguments = arguments.clone();
            if let (Some(next), Value::Object(object)) = (&cursor, &mut page_arguments) {
                drop(object.insert("cursor".to_owned(), json!(next)));
            }
            let reply = rig.call(tool, page_arguments).await?;
            let value = reply.ok()?;
            items.extend(
                value
                    .get(member)
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("no {member}: {value}"))?
                    .iter()
                    .cloned(),
            );
            cursor = value
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if cursor.is_none() {
                return Ok(items);
            }
        }
        Err("more than ten pages".into())
    }

    /// The characters of the string `key` of `item`.
    fn length(item: &Value, key: &str) -> TestResult<usize> {
        Ok(item
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no {key}: {item}"))?
            .chars()
            .count())
    }

    /// Todo 17: an oversized version does not stop paging.
    ///
    /// The version is longer than the default result cap; every package still arrives over
    /// the cursor, and the long version is cut to 128 characters and marked `cut`, with
    /// its control characters still removed.
    #[tokio::test]
    async fn an_oversized_version_is_cut_and_paging_goes_on() -> TestResult {
        let huge = format!("1.0\u{1b}[31m\u{7}{}", "9".repeat(40_000));
        let userland = Config::default()
            .installed("a-first", "1.0-1")
            .installed("b-huge", &huge)
            .installed("c-last", "1.0-1");
        let rig = Rig::start(Setup::new(every(), admin()).ssh(userland)).await?;
        let list = json!({"host": "lab-1", "confirm": true, "op": "list"});
        let packages = every_page(&rig, PACKAGES, list, "packages").await?;
        let names = packages
            .iter()
            .filter_map(|item| item.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(names, ["a-first", "b-huge", "c-last"]);
        let cut = packages.get(1).ok_or("no b-huge")?;
        assert!(length(cut, "version")? <= VERSION_CHARS, "{cut}");
        assert_eq!(cut.get("cut"), Some(&json!(true)), "{cut}");
        let version = cut
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(version.starts_with("1.09"), "{version}");
        assert!(!version.chars().any(char::is_control), "{version}");
        assert_eq!(
            packages.first(),
            Some(&json!({"name": "a-first", "version": "1.0-1"}))
        );
        rig.stop().await
    }

    /// Todo 17: a 6000-character log message is delivered cut to 1024 characters and
    /// marked `cut`; its control characters are removed.
    #[tokio::test]
    async fn an_oversized_log_message_is_cut() -> TestResult {
        let userland = Config::default().service("S51dropbear", Service::new("dropbear").running());
        let rig = Rig::start(Setup::new(every(), admin()).ssh(userland)).await?;
        let oversized = format!("\u{1b}[31m{}\u{7}", "x".repeat(6000));
        rig.router()
            .insert_log(10, record("I", &format!("dropbear[1]: {oversized}")));
        rig.router()
            .insert_log(11, record("I", "dropbear[1]: short"));
        let log = json!({"host": "lab-1", "confirm": true, "op": "log", "service": "S51dropbear"});
        let records = every_page(&rig, SERVICES, log, "records").await?;
        let lengths = records
            .iter()
            .map(|item| length(item, "message"))
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(lengths.len(), 2, "{records:?}");
        let cut = records.first().ok_or("no record")?;
        assert!(length(cut, "message")? <= MESSAGE_CHARS, "{cut}");
        assert!(length(cut, "message")? > 1000, "{cut}");
        assert_eq!(cut.get("cut"), Some(&json!(true)), "{cut}");
        let message = cut
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!message.chars().any(char::is_control), "{message}");
        assert_eq!(records.get(1).and_then(|item| item.get("cut")), None);
        rig.stop().await
    }
}
