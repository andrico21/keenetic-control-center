//! Wi-Fi commands.

use kcc_app::permissions::Permission;
use kcc_domain::wifi::{self, Encryption};

use super::{
    args_dom_link::{EncryptionChoice, WifiCommand},
    context::Ctx,
    dom_net::new_secret,
    dom_wire::object,
    domains::Session,
    exit::Outcome,
};

/// Runs a `wifi` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn wifi(ctx: &Ctx, command: WifiCommand) -> Outcome {
    let permission = match command {
        WifiCommand::Radios | WifiCommand::Ap { ap: _ } | WifiCommand::Stations => Permission::Read,
        WifiCommand::SetSsid { ap: _, ssid: _ }
        | WifiCommand::SetPsk { ap: _ }
        | WifiCommand::Hide { ap: _, state: _ }
        | WifiCommand::Enable { ap: _, state: _ }
        | WifiCommand::Channel { ap: _, channel: _ }
        | WifiCommand::Power { ap: _, power: _ }
        | WifiCommand::Country { ap: _, code: _ }
        | WifiCommand::Encryption { ap: _, mode: _ }
        | WifiCommand::Schedule { ap: _, schedule: _ }
        | WifiCommand::ChannelWidth { ap: _, width: _ }
        | WifiCommand::BandSteering { ap: _, state: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let (name, operation) = match command {
        WifiCommand::Radios => return session.show(&wifi::read_radios(router).await?),
        WifiCommand::Stations => return session.show(&wifi::read_stations(router).await?),
        WifiCommand::Ap { ap } => {
            return session.show(&wifi::read_access_point(router, &object(&ap)?).await?);
        }
        WifiCommand::SetSsid { ap, ssid } => {
            let name = object(&ap)?;
            let operation = wifi::plan_ssid(router, &name, &ssid)?;
            (name, operation)
        }
        WifiCommand::SetPsk { ap } => {
            let name = object(&ap)?;
            let key = new_secret(ctx, &ap)?;
            let operation = wifi::plan_wpa_psk(router, &name, key)?;
            (name, operation)
        }
        WifiCommand::Hide { ap, state } => {
            let name = object(&ap)?;
            let operation = wifi::plan_hide_ssid(router, &name, state.enabled())?;
            (name, operation)
        }
        WifiCommand::Enable { ap, state } => {
            let name = object(&ap)?;
            let operation = wifi::plan_up(router, &name, state.enabled()).await?;
            (name, operation)
        }
        WifiCommand::Channel { ap, channel } => {
            let name = object(&ap)?;
            let operation = wifi::plan_channel(router, &name, &channel)?;
            (name, operation)
        }
        WifiCommand::Power { ap, power } => {
            let name = object(&ap)?;
            let operation = wifi::plan_power(router, &name, power)?;
            (name, operation)
        }
        WifiCommand::Country { ap, code } => {
            let name = object(&ap)?;
            let operation = wifi::plan_country_code(router, &name, &code)?;
            (name, operation)
        }
        WifiCommand::Encryption { ap, mode } => {
            let name = object(&ap)?;
            let encryption = match mode {
                EncryptionChoice::Enable => Encryption::Enable,
                EncryptionChoice::Wpa2 => Encryption::Wpa2,
                EncryptionChoice::Wpa3 => Encryption::Wpa3,
            };
            let operation = wifi::plan_encryption(router, &name, encryption)?;
            (name, operation)
        }
        WifiCommand::Schedule { ap, schedule } => {
            let name = object(&ap)?;
            let operation = wifi::plan_schedule(router, &name, &schedule).await?;
            (name, operation)
        }
        WifiCommand::ChannelWidth { ap, width } => {
            let name = object(&ap)?;
            let operation = wifi::plan_channel_width(router, &name, &width)?;
            (name, operation)
        }
        WifiCommand::BandSteering { ap, state } => {
            let name = object(&ap)?;
            let operation = wifi::plan_band_steering(router, &name, state.enabled())?;
            (name, operation)
        }
    };
    session
        .cli(&operation, wifi::change_request(&name, &operation)?)
        .await
}
