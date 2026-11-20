//! Telegram notifications: a Bot API client that only sends messages, and the delivery
//! outbox that merges, paces and retries them.
//!
//! The Bot API base URL comes only from `kcc.toml`. The client uses no proxy, follows no
//! redirect and resolves host names through [`dns::PolicyResolver`], which drops
//! every address no outbound-policy setting could admit. The bot token travels in the URL
//! path, so no request URL is ever logged and every transport error is stripped of it.

pub mod bot;
pub mod delivery;
pub mod dns;
pub mod failure;
pub mod text;
