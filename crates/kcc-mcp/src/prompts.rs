//! Localized MCP prompt inventory.

use kcc_i18n::{bundle::MessageKey, keys};

/// Every prompt the server offers: protocol name, English description, body key.
pub(crate) const PROMPTS: &[(&str, &str, MessageKey)] = &[
    (
        "troubleshoot_internet",
        "Safely diagnose internet connectivity",
        keys::MCP_PROMPT_TROUBLESHOOT_INTERNET,
    ),
    (
        "troubleshoot_wifi",
        "Safely diagnose Wi-Fi connectivity",
        keys::MCP_PROMPT_TROUBLESHOOT_WIFI,
    ),
    (
        "troubleshoot_device",
        "Safely diagnose one client device",
        keys::MCP_PROMPT_TROUBLESHOOT_DEVICE,
    ),
    (
        "safe_change_workflow",
        "Plan, apply, verify, and explicitly save a safe change",
        keys::MCP_PROMPT_SAFE_CHANGE_WORKFLOW,
    ),
];
