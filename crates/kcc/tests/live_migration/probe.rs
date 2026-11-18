//! Value-free observations: per-line context labels and the realm-bound hash probe.

use core::{error::Error, fmt, hash::BuildHasher as _};
use std::hash::RandomState;

use kcc_app::settings::OutboundConfig;
use kcc_migrate::{planner::MigrationPlan, source::SourceConfig};
use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciClient, RciClientOptions, RciError, RciPath, RouterUrl,
    auth::Credentials,
};
use kcc_testkit::ndw2;
use secrecy::SecretString;

/// Temporary account created only for the hash probe and removed afterwards.
pub(crate) const PROBE_USER: &str = "kccprobe";

/// Labels every planned line by its context type, never by its arguments.
pub(crate) fn planned_lines(plan: &MigrationPlan) -> Vec<(usize, String)> {
    plan.phases
        .additive
        .iter()
        .chain(&plan.phases.prune)
        .chain(&plan.phases.management)
        .map(|line| (line.source_index, context(line.expose_command())))
        .collect()
}

/// Context type of one full-path line, e.g. `interface:Bridge` or `ip dhcp pool`.
fn context(line: &str) -> String {
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["no", ..] => "no".to_owned(),
        ["interface", name, ..] => {
            let kind = name.trim_end_matches(|character: char| {
                character.is_ascii_digit() || matches!(character, '/' | '.')
            });
            format!("interface:{}", kind.split('/').next().unwrap_or(kind))
        }
        ["ip", "dhcp", "pool", ..] => "ip dhcp pool".to_owned(),
        ["ip", "policy", ..] => "ip policy".to_owned(),
        ["user", _name, field, ..] => format!("user:{field}"),
        ["access-list" | "schedule", ..] => words
            .first()
            .map_or_else(String::new, |first| (*first).to_owned()),
        [first, second, ..] => format!("top-level:{first} {second}"),
        [first] => format!("top-level:{first}"),
        [] => "empty".to_owned(),
    }
}

/// The admitted target the probe writes to and signs in to.
pub(crate) struct Probe<'probe> {
    /// The admitted administrator connection.
    pub client: &'probe RciClient,
    /// Target origin.
    pub url: &'probe str,
    /// Outbound policy of the admitted configuration.
    pub outbound: &'probe OutboundConfig,
}

/// The authentication realms of the source and the target.
#[derive(Clone, Copy)]
pub(crate) struct Realms<'realm> {
    /// Realm named by the source configuration header.
    pub source: &'realm str,
    /// Realm the target reports.
    pub target: &'realm str,
}

/// Both realms, or `None` when the source header or the target leaves one unknown.
pub(crate) fn realms<'realm>(
    config: &'realm SourceConfig,
    target: Option<&'realm str>,
) -> Option<Realms<'realm>> {
    let source = config
        .header
        .model
        .as_deref()
        .filter(|model| model.contains(' '))?;
    Some(Realms {
        source,
        target: target?,
    })
}

/// What the probe observed once its target-realm control authenticated.
pub(crate) struct Observed {
    /// The source-realm hash authenticated on the target.
    pub source_accepted: bool,
}

/// The target refused the hash built with its own realm, so the source-realm result says
/// nothing about realm binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlRefused;

impl fmt::Display for ControlRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the target refused its own realm's hash; the probe proves nothing")
    }
}

impl Error for ControlRefused {}

/// Arms the fail-safe timer: an account left behind is rolled back after 900 s.
const ARM: &str = "system configuration fail-safe timer reboot 900";

/// Disarms the fail-safe timer once the probe account is gone.
const DISARM: &str = "no system configuration fail-safe timer";

/// Whether a source-realm hash authenticates on the target, checked against a control.
///
/// The control is the hash built with the target's own realm. The account exists only under
/// the armed fail-safe timer and is removed on every path; the timer stays armed when the
/// removal fails.
///
/// # Errors
/// Returns probe command failures, the removal failure, or [`ControlRefused`].
// NOT cancel-safe: creates and removes a temporary account; the armed timer rolls back an
// interrupted probe and nothing is saved.
pub(crate) async fn password_hash(
    probe: &Probe<'_>,
    realms: Realms<'_>,
) -> Result<Observed, Box<dyn Error>> {
    write(probe.client, ARM).await?;
    // The failure text is kept instead of the boxed error so the future stays `Send`.
    let attempts = attempts(probe, realms)
        .await
        .map_err(|error| error.to_string());
    write(probe.client, &format!("no user {PROBE_USER}")).await?;
    write(probe.client, DISARM).await?;
    let [source_accepted, target_accepted] = attempts?;
    if !target_accepted {
        return Err(ControlRefused.into());
    }
    Ok(Observed { source_accepted })
}

/// Sets the probe account's hash for the source realm, then the target realm, and signs in
/// after each.
///
/// # Errors
/// Returns probe command failures; login refusals are observations.
// NOT cancel-safe: changes the probe account on the router.
async fn attempts(probe: &Probe<'_>, realms: Realms<'_>) -> Result<[bool; 2], Box<dyn Error>> {
    let password = format!("{:016x}", RandomState::new().hash_one(PROBE_USER));
    let mut accepted = [false; 2];
    for (slot, realm) in accepted.iter_mut().zip([realms.source, realms.target]) {
        let hash = ndw2::ha1(PROBE_USER, realm, &password);
        write(
            probe.client,
            &format!("user {PROBE_USER} password md5 {}", hash.as_str()),
        )
        .await?;
        write(probe.client, &format!("user {PROBE_USER} tag readonly")).await?;
        *slot = login(probe, &password).await;
    }
    Ok(accepted)
}

/// Sends one parser line after a read that renews the session: a password change may end
/// every router session, and a parser line is never replayed after a 401.
///
/// # Errors
/// Returns the read or parser failure.
// NOT cancel-safe: the line may apply before cancellation.
async fn write(client: &RciClient, line: &str) -> Result<(), Box<dyn Error>> {
    let path = RciPath::from_segments(["show", "identification"])?;
    drop(client.get(&path, &()).await?);
    drop(client.parse(line).await?);
    Ok(())
}

/// Attempts a fresh login as the probe account under the admitted outbound policy.
// cancel-safe: authentication only.
async fn login(probe: &Probe<'_>, password: &str) -> bool {
    let Ok(url) = probe.url.parse::<RouterUrl>() else {
        return false;
    };
    let Ok(policy) = policy(probe.outbound) else {
        return false;
    };
    let credentials = Credentials::new(
        PROBE_USER.to_owned(),
        SecretString::from(password.to_owned()),
    );
    let options = RciClientOptions::default().with_outbound(policy);
    let Ok(client) = RciClient::connect_with(url, credentials, options).await else {
        return false;
    };
    let Ok(path) = RciPath::from_segments(["show", "identification"]) else {
        return false;
    };
    client.get(&path, &()).await.is_ok()
}

/// The outbound policy of a kcc configuration, as the router registry builds it.
fn policy(outbound: &OutboundConfig) -> Result<OutboundPolicy, RciError> {
    let networks = outbound
        .allowed_networks
        .iter()
        .map(|network| AllowedNetwork::new(network.addr(), network.prefix_len()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OutboundPolicy::default()
        .with_allowed_networks(networks)
        .with_allowed_suffixes(outbound.allowed_suffixes.clone())
        .with_loopback(outbound.allow_loopback))
}
