//! Listings over the result cap: packages, services and log records are paged with the
//! shared cursor until every item was read exactly once.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the pages"
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

    /// Items each listing holds.
    const ITEMS: u32 = 40;

    /// Every page of `tool` called with `arguments`: the `key` member of every item of
    /// `member`, and the number of pages.
    async fn pages(
        rig: &Rig,
        (tool, arguments): (&str, Value),
        (member, key): (&str, &str),
    ) -> TestResult<(Vec<String>, u32)> {
        let (mut seen, mut count, mut cursor) = (Vec::new(), 0_u32, None::<String>);
        loop {
            let mut page_arguments = arguments.clone();
            if let (Some(next), Value::Object(object)) = (&cursor, &mut page_arguments) {
                drop(object.insert("cursor".to_owned(), json!(next)));
            }
            let reply = rig.call(tool, page_arguments).await?;
            let value = reply.ok()?;
            let items = value
                .get(member)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("no {member}: {value}"))?;
            seen.extend(items.iter().filter_map(|item| item.get(key)).map(|found| {
                found
                    .as_str()
                    .map_or_else(|| found.to_string(), str::to_owned)
            }));
            count = count.saturating_add(1);
            cursor = value
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if cursor.is_none() || count > ITEMS {
                return Ok((seen, count));
            }
            assert_eq!(value.get("truncated"), Some(&json!(true)), "{value}");
        }
    }

    /// Todo 17: listings over the result cap answer pages with `next_cursor`; following it
    /// returns every package, service and log record exactly once, in order.
    #[tokio::test]
    async fn listings_over_the_cap_are_paged() -> TestResult {
        let names = (0..ITEMS).map(|index| format!("pkg-{index:02}"));
        let services = (0..ITEMS).map(|index| format!("S10svc{index:02}"));
        let userland = names.clone().zip(services.clone()).fold(
            Config::default().service("S51dropbear", Service::new("dropbear").running()),
            |config, (name, service)| {
                config
                    .installed(&name, "1.0-1")
                    .service(&service, Service::new("svc"))
            },
        );
        let mut capped = every();
        capped.max_result_bytes = 400;
        let rig = Rig::start(Setup::new(capped, admin()).ssh(userland)).await?;
        for id in 1..=u64::from(ITEMS) {
            rig.router()
                .insert_log(id, record("I", &format!("dropbear[1]: line {id}")));
        }
        let base = json!({"host": "lab-1", "confirm": true, "op": "list"});
        let (packages, package_pages) =
            pages(&rig, (PACKAGES, base.clone()), ("packages", "name")).await?;
        assert!(package_pages > 1, "one package page only");
        assert_eq!(packages, names.collect::<Vec<_>>());

        let (listed, service_pages) = pages(&rig, (SERVICES, base), ("services", "name")).await?;
        assert!(service_pages > 1, "one service page only");
        let mut expected = services.collect::<Vec<_>>();
        expected.push("S51dropbear".to_owned());
        assert_eq!(listed, expected);

        let log = json!({"host": "lab-1", "confirm": true, "op": "log", "service": "S51dropbear"});
        let (records, log_pages) = pages(&rig, (SERVICES, log), ("records", "id")).await?;
        assert!(log_pages > 1, "one log page only");
        assert_eq!(
            records,
            (1..=u64::from(ITEMS))
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
        );
        rig.stop().await
    }
}
