//! Free text reaches a router CLI line as one quoted word; identifiers as one bare token.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the CLI word contract"
)]
mod tests {
    use core::net::Ipv4Addr;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use kcc_domain::{
        DomainError, clients,
        dhcp::{self, model::PoolConfig},
        dns::{self, DnsChange},
        firewall::{
            change,
            model::{Action, Direction, Protocol, Rule},
        },
        policies::change::{apply, plan},
        schedules,
        vpn_clients::{self, VpnClientChange},
        vpn_servers::{self, VpnServerChange},
    };

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Whether the fake router received exactly `line` as a parse command.
    fn received(fixture: &Fixture, line: &str) -> bool {
        fixture
            .handle()
            .request_log()
            .iter()
            .any(|record| record.command() == Some(line))
    }

    /// Whether `outcome` is the planner's refusal of a value that is not one CLI word.
    const fn refused<T>(outcome: &kcc_domain::Result<T>) -> bool {
        matches!(outcome, Err(DomainError::InvalidCliToken))
    }

    /// SEC2-02, C-01: a registration name with a space is sent as one quoted word, and
    /// the router reports the name unchanged.
    #[tokio::test]
    async fn registration_name_with_a_space_is_one_quoted_word() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let mac = "02:00:00:00:10:aa";
            let operation = clients::plan_register(fixture.context(), mac.parse()?, "Anna phone")?;
            let mut changes = fixture.changes().await?;
            drop(clients::apply(&mut changes, fixture.context(), &operation).await?);
            drop(changes);
            assert!(received(
                &fixture,
                &format!("known host \"Anna phone\" {mac}")
            ));
            let client = clients::read_client(fixture.context(), mac).await?;
            assert_eq!(
                client.and_then(|row| row.name).as_deref(),
                Some("Anna phone")
            );
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// SEC2-02, C-01: registering an unknown client under an empty name is refused before
    /// anything is sent, instead of sending `known host  <mac>`.
    #[tokio::test]
    async fn empty_registration_name_is_refused() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let client = clients::read_client(fixture.context(), "02:00:00:00:10:02")
                .await?
                .ok_or("fixture client")?;
            assert_eq!(client.registered, Some(false));
            let planned =
                clients::plan_access(fixture.context(), &client, "", clients::Access::Deny);
            assert!(refused(&planned), "{planned:?}");
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// SEC2-02, C-01: a DHCP pool name is an identifier, so words smuggled after it are
    /// refused rather than becoming pool subcommand arguments.
    #[tokio::test]
    async fn dhcp_pool_name_with_words_is_refused() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let private = 10_u8;
            let name = format!("Home range {private}.0.0.2 {private}.0.0.3");
            let pool = PoolConfig::new(
                name,
                Ipv4Addr::new(192, 0, 2, 80),
                Ipv4Addr::new(192, 0, 2, 120),
            );
            let planned = dhcp::plan_pool(fixture.context(), &pool);
            assert!(refused(&planned), "{planned:?}");
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-02: DNS names are single tokens, and a DNS profile description is planned as one
    /// quoted word (the fake router has no filter-profile grammar to receive it).
    #[tokio::test]
    async fn dns_names_are_tokens_and_descriptions_are_quoted() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let smuggled = dns::plan_change(
                fixture.context(),
                &DnsChange::FqdnGroup {
                    name: "G include evil.example".to_owned(),
                },
            );
            assert!(refused(&smuggled), "{smuggled:?}");
            let described = dns::plan_change(
                fixture.context(),
                &DnsChange::FilterProfileDescription {
                    name: "kids".to_owned(),
                    description: "Streaming services".to_owned(),
                },
            )?;
            let request = dns::change_request(&described)?;
            let lines = request
                .commands
                .iter()
                .map(|command| Ok(command.expose_for_send()?.to_string()))
                .collect::<TestResult<Vec<_>>>()?;
            assert_eq!(
                lines,
                ["dns-proxy filter profile description kids \"Streaming services\""]
            );
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-02: VPN context names, WireGuard peer keys and crypto-map names are single tokens.
    #[tokio::test]
    async fn vpn_context_names_and_peer_keys_are_tokens() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let key = STANDARD.encode([7_u8; 32]);
            let context = vpn_clients::plan_change(
                fixture.context(),
                &VpnClientChange::WireGuardListenPort {
                    name: format!("Wireguard0 wireguard peer {key}"),
                    port: 51_820,
                },
            )
            .await;
            assert!(refused(&context), "{context:?}");
            let peer = vpn_clients::plan_change(
                fixture.context(),
                &VpnClientChange::WireGuardKeepalive {
                    name: "Wireguard0".to_owned(),
                    public_key: format!("{key} endpoint 203.0.113.9:51820"),
                    seconds: 25,
                },
            )
            .await;
            assert!(refused(&peer), "{peer:?}");
            let map = vpn_servers::plan_change(
                fixture.context(),
                &VpnServerChange::IpsecMap {
                    name: "VPN1 virtual-ip enable".to_owned(),
                },
            );
            assert!(refused(&map), "{map:?}");
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-02: a connection-policy description with a space is one quoted word.
    #[tokio::test]
    async fn policy_description_is_one_quoted_word() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let name = "Policy9";
            let mut changes = fixture.changes().await?;
            let create = plan::create(fixture.context(), name)?;
            drop(apply::apply(&mut changes, fixture.context(), &create).await?);
            let described = plan::description(fixture.context(), name, Some("Uplink policy"))?;
            drop(apply::apply(&mut changes, fixture.context(), &described).await?);
            drop(changes);
            assert!(received(
                &fixture,
                "ip policy Policy9 description \"Uplink policy\""
            ));
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// D-02, N7: an access-list name is one identifier, so a name with spaces is refused
    /// before management classification can miss the bound list.
    #[tokio::test]
    async fn access_list_name_with_spaces_is_refused() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let rule = Rule::new(Action::Deny, Protocol::Udp, "0.0.0.0", "198.51.100.20");
            let added = change::plan_add_rule(fixture.context(), "WAN_IN extra", &rule);
            assert!(refused(&added), "{added:?}");
            let bound =
                change::plan_bind(fixture.context(), "ISP", "WebAcl in", Direction::In, true);
            assert!(refused(&bound), "{bound:?}");
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// C-20: a schedule description with a space is sent as one quoted word.
    #[tokio::test]
    async fn schedule_description_with_a_space_is_one_quoted_word() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let operation =
                schedules::plan_description(fixture.context(), "Schedule0", "Night mode")?;
            let mut changes = fixture.changes().await?;
            drop(
                changes
                    .apply_cli(schedules::change_request(&operation)?)
                    .await?,
            );
            drop(changes);
            assert!(received(
                &fixture,
                "schedule Schedule0 description \"Night mode\""
            ));
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
