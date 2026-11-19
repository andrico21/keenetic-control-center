//! The chats notifications go to: checked ids and labels, at most [`MAX_CHATS`].

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::NotifyError;

/// Most chats one installation sends to.
pub const MAX_CHATS: usize = 10;

/// A Telegram chat id: a non-zero integer (kept in its canonical decimal form) or a
/// public `@username` of 5 to 32 ASCII letters, digits and `_`. Stored as text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct ChatId(String);

impl ChatId {
    /// Checks and canonicalizes `text` (`+42` becomes `42`).
    ///
    /// # Errors
    ///
    /// [`NotifyError::Invalid`] naming `chats.id`.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, NotifyError> {
        let refused = NotifyError::Invalid { field: "chats.id" };
        if let Some(name) = text.strip_prefix('@') {
            let valid = (5..=32).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
            return valid.then(|| Self(text.to_owned())).ok_or(refused);
        }
        match text.parse::<i64>() {
            Ok(id) if id != 0 => Ok(Self(id.to_string())),
            Ok(_) | Err(_) => Err(refused),
        }
    }

    /// The id as stored: the decimal integer or the `@username`.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The integer id, or `None` for an `@username`.
    #[inline]
    #[must_use]
    pub fn numeric(&self) -> Option<i64> {
        self.0.parse().ok()
    }
}

impl Serialize for ChatId {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ChatId {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// A chat's display label: 1 to 64 characters, no control characters.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChatLabel(String);

impl ChatLabel {
    /// Checks `text`.
    ///
    /// # Errors
    ///
    /// [`NotifyError::Invalid`] naming `chats.label`.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, NotifyError> {
        let valid = (1..=64).contains(&text.chars().count()) && !text.chars().any(char::is_control);
        valid
            .then(|| Self(text.to_owned()))
            .ok_or(NotifyError::Invalid {
                field: "chats.label",
            })
    }

    /// The label.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for ChatLabel {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ChatLabel {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// One chat messages go to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Chat {
    /// The chat.
    pub id: ChatId,
    /// What the admin pages call it.
    pub label: ChatLabel,
    /// Forum topic (`message_thread_id`) to post in.
    #[serde(default)]
    pub thread: Option<i64>,
    /// Send without a notification sound.
    #[serde(default)]
    pub silent: bool,
}

impl Chat {
    /// A chat in its main thread, with sound.
    #[inline]
    #[must_use]
    pub const fn new(id: ChatId, label: ChatLabel) -> Self {
        Self {
            id,
            label,
            thread: None,
            silent: false,
        }
    }
}

/// At most [`MAX_CHATS`] chats with distinct ids.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
#[non_exhaustive]
pub struct Chats(Vec<Chat>);

impl Chats {
    /// Checks the count and that no id repeats.
    ///
    /// # Errors
    ///
    /// [`NotifyError::Invalid`] naming `chats`.
    #[inline]
    pub fn new(chats: Vec<Chat>) -> Result<Self, NotifyError> {
        let distinct = chats.iter().enumerate().all(|(index, chat)| {
            chats
                .iter()
                .skip(index.saturating_add(1))
                .all(|other| other.id != chat.id)
        });
        (chats.len() <= MAX_CHATS && distinct).ok_or(NotifyError::Invalid { field: "chats" })?;
        Ok(Self(chats))
    }

    /// The chats, in the admin's order.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[Chat] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Chats {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
