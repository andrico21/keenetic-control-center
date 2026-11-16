//! KeenDNS proxy upstream: the line sent is the line validated, for every host form.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the proxy upstream contract"
)]
mod tests {
    use kcc_domain::{DomainError, keendns};

    use crate::support::{Fixture, PROFILES, TestResult, refused_by_catalog};

    /// C-07: a LAN host name, an IP and a MAC upstream are each validated as the line
    /// sent, reach the router exactly as planned and pass the read-back.
    #[tokio::test]
    async fn host_name_ip_and_mac_upstreams_are_sent_as_validated() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            for (protocol, host) in [
                ("http", "nas.lan"),
                ("https", "192.0.2.67"),
                ("connect", "02:00:00:00:53:43"),
            ] {
                let line = format!("ip http proxy proxy67 upstream {protocol} {host} 8080");
                let operation = keendns::plan_proxy_upstream(ctx, "proxy67", protocol, host, 8_080)
                    .map_err(|error| format!("{firmware:?} {host}: {error:?}"))?;
                let before = fixture.handle().request_log().len();
                let mut changes = fixture.changes().await?;
                drop(
                    changes
                        .apply_cli(keendns::change_request(&operation)?)
                        .await?,
                );
                drop(changes);
                let sent = fixture
                    .handle()
                    .request_log()
                    .iter()
                    .skip(before)
                    .filter_map(|record| record.command().map(str::to_owned))
                    .filter(|command| command.contains(" upstream "))
                    .collect::<Vec<_>>();
                assert_eq!(sent, [line], "{firmware:?}");
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// C-07: an unknown protocol, a host that is not one CLI word and port 0 are refused
    /// before any request.
    #[tokio::test]
    async fn malformed_upstreams_are_refused() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let ctx = fixture.context();
            let before = fixture.handle().request_count();
            assert!(refused_by_catalog(&keendns::plan_proxy_upstream(
                ctx,
                "proxy67",
                "ftp",
                "192.0.2.67",
                8_080
            )));
            for host in ["nas lan", "nas\u{7}lan", ""] {
                assert!(
                    matches!(
                        keendns::plan_proxy_upstream(ctx, "proxy67", "http", host, 8_080),
                        Err(DomainError::InvalidCliToken)
                    ),
                    "{host:?}"
                );
            }
            assert!(refused_by_catalog(&keendns::plan_proxy_upstream(
                ctx,
                "proxy67",
                "http",
                "192.0.2.67",
                0
            )));
            assert_eq!(fixture.handle().request_count(), before);
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
