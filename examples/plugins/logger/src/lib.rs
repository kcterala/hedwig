//! # Hedwig Logger Plugin
//!
//! An example WASM plugin for Hedwig SMTP server that logs email lifecycle events.
//!
//! This plugin demonstrates how to:
//! - Handle multiple hooks (on_mail_from, on_rcpt_to, on_data, after_send, on_bounce)
//! - Use host functions for logging
//! - Read plugin configuration
//! - Return hook responses with metadata
//!
//! ## Building
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown
//! ```
//!
//! ## Configuration
//!
//! ```toml
//! [[plugins]]
//! name = "logger"
//! path = "/path/to/hedwig_plugin_logger.wasm"
//! hooks = ["on_mail_from", "on_rcpt_to", "on_data", "after_send", "on_bounce"]
//!
//! [plugins.config]
//! log_headers = false
//! log_body = false
//! ```

use extism_pdk::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Input passed to plugin hooks from Hedwig
#[derive(Debug, Deserialize)]
struct HookInput {
    /// The hook being called
    hook: String,
    /// Unique message identifier
    message_id: String,
    /// Sender email address
    from: String,
    /// Recipient email addresses
    to: Vec<String>,
    /// Email subject (available in on_data and later hooks)
    #[serde(default)]
    subject: Option<String>,
    /// Email headers (available in on_data and later hooks)
    #[serde(default)]
    headers: HashMap<String, String>,
    /// Email body (available if configured, in on_data and later hooks)
    #[serde(default)]
    body: Option<String>,
    /// Size of the email body in bytes
    #[serde(default)]
    body_size: Option<usize>,
    /// Plugin-specific configuration from config.toml
    #[serde(default)]
    plugin_config: PluginConfig,
    /// Metadata passed from previous plugins or hooks
    #[serde(default)]
    metadata: HashMap<String, serde_json::Value>,
}

/// Plugin configuration from config.toml [plugins.config] section
#[derive(Debug, Default, Deserialize)]
struct PluginConfig {
    /// Whether to log email headers
    #[serde(default)]
    log_headers: bool,
    /// Whether to log email body
    #[serde(default)]
    log_body: bool,
}

/// Output returned from plugin hooks to Hedwig
#[derive(Debug, Serialize)]
struct HookOutput {
    /// Action to take: "continue", "reject", or "defer"
    action: String,
    /// Optional message (used for reject/defer responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Metadata to pass to subsequent plugins/hooks
    #[serde(default)]
    metadata: HashMap<String, serde_json::Value>,
}

impl HookOutput {
    /// Create a continue response
    fn continue_with(metadata: HashMap<String, serde_json::Value>) -> Self {
        Self {
            action: "continue".to_string(),
            message: None,
            metadata,
        }
    }
}

// Host functions provided by Hedwig for logging
#[host_fn]
extern "ExtismHost" {
    fn log_info(message: &str);
    fn log_warn(message: &str);
    fn log_error(message: &str);
}

/// Hook called when MAIL FROM command is received
///
/// This is the earliest hook in the email lifecycle. Use it for:
/// - Sender validation
/// - Reputation checks
/// - Early rejection of known bad senders
#[plugin_fn]
pub fn on_mail_from(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    unsafe {
        log_info(&format!(
            "[{}] MAIL FROM: {}",
            input.message_id, input.from
        ))?;
    }

    let output = HookOutput::continue_with(HashMap::new());
    Ok(serde_json::to_string(&output)?)
}

/// Hook called when RCPT TO command is received
///
/// Called for each recipient. Use it for:
/// - Recipient validation
/// - Routing decisions
/// - Per-recipient filtering
#[plugin_fn]
pub fn on_rcpt_to(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    unsafe {
        log_info(&format!(
            "[{}] RCPT TO: {:?} (from: {})",
            input.message_id, input.to, input.from
        ))?;
    }

    let output = HookOutput::continue_with(HashMap::new());
    Ok(serde_json::to_string(&output)?)
}

/// Hook called when email data is received (after DATA command)
///
/// This is where you have access to the full email. Use it for:
/// - Spam filtering
/// - Content inspection
/// - Header analysis
/// - Virus scanning (via external service)
#[plugin_fn]
pub fn on_data(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    unsafe {
        log_info(&format!(
            "[{}] Email received: from={}, to={:?}, subject={:?}, size={:?} bytes",
            input.message_id,
            input.from,
            input.to,
            input.subject,
            input.body_size,
        ))?;

        // Optionally log headers if configured
        if input.plugin_config.log_headers && !input.headers.is_empty() {
            log_info(&format!("[{}] Headers: {:?}", input.message_id, input.headers))?;
        }

        // Optionally log body if configured
        if input.plugin_config.log_body {
            if let Some(body) = &input.body {
                let preview = if body.len() > 200 {
                    format!("{}...", &body[..200])
                } else {
                    body.clone()
                };
                log_info(&format!("[{}] Body preview: {}", input.message_id, preview))?;
            }
        }
    }

    // Add metadata indicating this email was logged
    let mut metadata = HashMap::new();
    metadata.insert(
        "logger_processed".to_string(),
        serde_json::Value::Bool(true),
    );
    metadata.insert(
        "logger_timestamp".to_string(),
        serde_json::Value::String(chrono_lite_now()),
    );

    let output = HookOutput::continue_with(metadata);
    Ok(serde_json::to_string(&output)?)
}

/// Hook called after email is successfully sent
///
/// Use this for:
/// - Audit logging
/// - Analytics
/// - Webhooks to external services
/// - Success notifications
#[plugin_fn]
pub fn after_send(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    unsafe {
        log_info(&format!(
            "[{}] Email sent successfully: from={}, to={:?}",
            input.message_id, input.from, input.to
        ))?;
    }

    let output = HookOutput::continue_with(HashMap::new());
    Ok(serde_json::to_string(&output)?)
}

/// Hook called when an email bounces
///
/// Use this for:
/// - Suppression list management
/// - Alerting
/// - Bounce analytics
/// - Notifying senders
#[plugin_fn]
pub fn on_bounce(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    unsafe {
        log_warn(&format!(
            "[{}] Email bounced: from={}, to={:?}",
            input.message_id, input.from, input.to
        ))?;
    }

    let output = HookOutput::continue_with(HashMap::new());
    Ok(serde_json::to_string(&output)?)
}

/// Simple timestamp function (WASM doesn't have std::time)
fn chrono_lite_now() -> String {
    // In a real plugin, you might want to pass the timestamp from the host
    // or use a WASM-compatible time library
    "logged".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_output_serialization() {
        let output = HookOutput::continue_with(HashMap::new());
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"action\":\"continue\""));
    }

    #[test]
    fn test_hook_input_deserialization() {
        let json = r#"{
            "hook": "on_data",
            "message_id": "test-123",
            "from": "sender@example.com",
            "to": ["recipient@example.com"],
            "subject": "Test Subject",
            "headers": {},
            "body_size": 1234,
            "plugin_config": {"log_headers": true},
            "metadata": {}
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.message_id, "test-123");
        assert_eq!(input.from, "sender@example.com");
        assert!(input.plugin_config.log_headers);
    }
}
