//! Simulated `media <name> initialize <preset>`: the medium shows no filesystem while the
//! router prepares it and its new filesystem from the third following `show media` read.

use alloc::collections::BTreeMap;

use serde_json::Value;

/// The `show media` read, counted from the `initialize` line, that shows the new filesystem.
const DONE_AT_READ: u8 = 3;

/// The media an `initialize` line named.
#[derive(Debug, Default)]
pub(super) struct MediaInit {
    /// Per medium id: the filesystem it gets and the reads left until it shows (0: shown).
    media: BTreeMap<String, (String, u8)>,
}

impl MediaInit {
    /// Starts initializing `name` with `preset` (`ntfs`, or ext4 for `ext4` and `default`).
    pub(super) fn start(&mut self, name: &str, preset: &str) {
        let filesystem = if preset == "ntfs" { "ntfs" } else { "ext4" };
        drop(
            self.media
                .insert(name.to_owned(), (filesystem.to_owned(), DONE_AT_READ)),
        );
    }

    /// Counts one `show media` read and shows each initialized medium's state in `answer`.
    pub(super) fn read(&mut self, answer: &mut Value) {
        let Some(volumes) = answer.as_array_mut() else {
            return;
        };
        for (name, (filesystem, left)) in &mut self.media {
            *left = left.saturating_sub(1);
            for fields in volumes
                .iter_mut()
                .filter(|volume| volume.get("id").and_then(Value::as_str) == Some(name.as_str()))
                .filter_map(Value::as_object_mut)
            {
                if *left == 0 {
                    drop(fields.insert("filesystem".to_owned(), Value::String(filesystem.clone())));
                } else {
                    drop(fields.remove("filesystem"));
                }
            }
        }
    }
}
