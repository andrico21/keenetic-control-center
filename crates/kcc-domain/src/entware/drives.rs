//! Which attached media `opkg disk` can use, and which can be initialized as ext4.

use alloc::collections::BTreeMap;

use serde_json::Value;

use super::models::EligibleDrive;
use crate::{cli_token, storage::MediaVolume};

/// The ext4-capable drives with their `opkg disk` argument: `<label>:/` when the label is
/// one CLI word and unique among all media, else `<uuid>:/` when the media has a uuid.
pub(super) fn eligible(media: &[MediaVolume]) -> Vec<EligibleDrive> {
    let mut labels = BTreeMap::<&str, usize>::new();
    for label in media.iter().filter_map(|volume| volume.label.as_deref()) {
        let count = labels.entry(label).or_default();
        *count = count.saturating_add(1);
    }
    media
        .iter()
        .filter_map(|volume| {
            let filesystem = volume
                .filesystem
                .as_deref()
                .filter(|name| ["ext2", "ext3", "ext4"].contains(name))?;
            let unique_label = volume
                .label
                .as_deref()
                .filter(|label| labels.get(label) == Some(&1) && word(label));
            let uuid = volume
                .extra
                .get("uuid")
                .and_then(Value::as_str)
                .filter(|uuid| word(uuid));
            let disk = unique_label.or(uuid)?;
            Some(EligibleDrive {
                media_id: volume.id.clone()?,
                disk_arg: format!("{disk}:/"),
                label: volume.label.clone(),
                filesystem: filesystem.to_owned(),
                free_bytes: volume.free,
            })
        })
        .collect()
}

/// The media whose `initialize-supported` list contains `ext4`.
pub(super) fn initializable(media: &[MediaVolume]) -> Vec<String> {
    media
        .iter()
        .filter(|volume| {
            volume
                .extra
                .get("initialize-supported")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("ext4")))
        })
        .filter_map(|volume| volume.id.clone())
        .collect()
}

/// The id of the one medium `device` (the part of an `opkg disk` argument before `:`)
/// names: by its uuid, compared without case, else by a label only that medium carries.
pub(super) fn resolve(media: &[MediaVolume], device: &str) -> Option<String> {
    let by_uuid = only(media.iter().filter(|volume| {
        volume
            .extra
            .get("uuid")
            .and_then(Value::as_str)
            .is_some_and(|uuid| uuid.eq_ignore_ascii_case(device))
    }));
    let volume = by_uuid.or_else(|| {
        only(
            media
                .iter()
                .filter(|volume| volume.label.as_deref() == Some(device)),
        )
    })?;
    volume.id.clone()
}

/// The single item of `matches`, or `None` for none or several.
fn only<'media, I>(mut matches: I) -> Option<&'media MediaVolume>
where
    I: Iterator<Item = &'media MediaVolume>,
{
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

/// Whether `value` is one safe router CLI word.
fn word(value: &str) -> bool {
    cli_token::validate(value).is_ok()
}
