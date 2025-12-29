use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Available hooks in the email lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    /// Triggered when MAIL FROM command is received.
    OnMailFrom,
    /// Triggered when RCPT TO command is received.
    OnRcptTo,
    /// Triggered when email body (DATA) is received.
    OnData,
    /// Triggered after email is successfully sent.
    AfterSend,
    /// Triggered when email bounces.
    OnBounce,
}

impl Hook {
    /// Returns the function name to call in the WASM plugin.
    pub fn function_name(&self) -> &'static str {
        match self {
            Hook::OnMailFrom => "on_mail_from",
            Hook::OnRcptTo => "on_rcpt_to",
            Hook::OnData => "on_data",
            Hook::AfterSend => "after_send",
            Hook::OnBounce => "on_bounce",
        }
    }

    /// Parse a hook from its string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "on_mail_from" => Some(Hook::OnMailFrom),
            "on_rcpt_to" => Some(Hook::OnRcptTo),
            "on_data" => Some(Hook::OnData),
            "after_send" => Some(Hook::AfterSend),
            "on_bounce" => Some(Hook::OnBounce),
            _ => None,
        }
    }
}

/// Action a plugin can request after processing a hook.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    /// Continue to next plugin/step.
    #[default]
    Continue,
    /// Reject the email with a message.
    Reject,
    /// Temporarily reject (retry later).
    Defer,
}

/// Input passed to plugin hooks (JSON serialized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInput {
    /// The hook being called.
    pub hook: Hook,
    /// Unique message identifier.
    pub message_id: String,
    /// Sender email address.
    pub from: String,
    /// Recipient email addresses.
    pub to: Vec<String>,
    /// Email subject (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Email headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Email body content (if available and requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Size of the email body in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_size: Option<usize>,
    /// Plugin-specific configuration from config.toml.
    pub plugin_config: serde_json::Value,
    /// Metadata accumulated from previous plugins.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Output returned from plugin hooks (JSON deserialized).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookOutput {
    /// Action the plugin requests.
    #[serde(default)]
    pub action: HookAction,
    /// Optional message (used for reject/defer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Metadata to pass to subsequent plugins/hooks.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Internal result after processing all plugins for a hook.
#[derive(Debug, Clone)]
pub enum HookResult {
    /// Continue with accumulated metadata.
    Continue(HashMap<String, serde_json::Value>),
    /// Reject the email with a message.
    Reject(String),
    /// Defer the email with a message.
    Defer(String),
}

impl Default for HookResult {
    fn default() -> Self {
        HookResult::Continue(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_function_names() {
        assert_eq!(Hook::OnMailFrom.function_name(), "on_mail_from");
        assert_eq!(Hook::OnRcptTo.function_name(), "on_rcpt_to");
        assert_eq!(Hook::OnData.function_name(), "on_data");
        assert_eq!(Hook::AfterSend.function_name(), "after_send");
        assert_eq!(Hook::OnBounce.function_name(), "on_bounce");
    }

    #[test]
    fn test_hook_from_str() {
        assert_eq!(Hook::from_str("on_mail_from"), Some(Hook::OnMailFrom));
        assert_eq!(Hook::from_str("on_rcpt_to"), Some(Hook::OnRcptTo));
        assert_eq!(Hook::from_str("on_data"), Some(Hook::OnData));
        assert_eq!(Hook::from_str("after_send"), Some(Hook::AfterSend));
        assert_eq!(Hook::from_str("on_bounce"), Some(Hook::OnBounce));
        assert_eq!(Hook::from_str("unknown"), None);
    }

    #[test]
    fn test_hook_action_default() {
        let action: HookAction = Default::default();
        assert_eq!(action, HookAction::Continue);
    }

    #[test]
    fn test_hook_output_serialization() {
        let output = HookOutput {
            action: HookAction::Continue,
            message: None,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"action\":\"continue\""));
    }

    #[test]
    fn test_hook_input_serialization() {
        let input = HookInput {
            hook: Hook::OnData,
            message_id: "test-123".to_string(),
            from: "sender@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            subject: Some("Test Subject".to_string()),
            headers: HashMap::new(),
            body: None,
            body_size: Some(100),
            plugin_config: serde_json::json!({"key": "value"}),
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"hook\":\"on_data\""));
        assert!(json.contains("\"message_id\":\"test-123\""));
    }

    #[test]
    fn test_hook_serialization_roundtrip() {
        for hook in [
            Hook::OnMailFrom,
            Hook::OnRcptTo,
            Hook::OnData,
            Hook::AfterSend,
            Hook::OnBounce,
        ] {
            let json = serde_json::to_string(&hook).unwrap();
            let deserialized: Hook = serde_json::from_str(&json).unwrap();
            assert_eq!(hook, deserialized);
        }
    }

    #[test]
    fn test_hook_action_serialization_roundtrip() {
        for action in [HookAction::Continue, HookAction::Reject, HookAction::Defer] {
            let json = serde_json::to_string(&action).unwrap();
            let deserialized: HookAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, deserialized);
        }
    }

    #[test]
    fn test_hook_output_deserialization_minimal() {
        let json = r#"{"action": "continue"}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.action, HookAction::Continue);
        assert!(output.message.is_none());
        assert!(output.metadata.is_empty());
    }

    #[test]
    fn test_hook_output_deserialization_with_message() {
        let json = r#"{"action": "reject", "message": "Spam detected"}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.action, HookAction::Reject);
        assert_eq!(output.message, Some("Spam detected".to_string()));
    }

    #[test]
    fn test_hook_output_deserialization_with_metadata() {
        let json = r#"{"action": "continue", "metadata": {"spam_score": 2.5, "checked": true}}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.action, HookAction::Continue);
        assert_eq!(
            output.metadata.get("spam_score"),
            Some(&serde_json::json!(2.5))
        );
        assert_eq!(
            output.metadata.get("checked"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn test_hook_input_deserialization() {
        let json = r#"{
            "hook": "on_data",
            "message_id": "msg-456",
            "from": "test@example.com",
            "to": ["a@b.com", "c@d.com"],
            "subject": "Hello",
            "headers": {"From": "test@example.com"},
            "body": "Email body",
            "body_size": 10,
            "plugin_config": {"threshold": 5.0},
            "metadata": {"previous": "value"}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.hook, Hook::OnData);
        assert_eq!(input.message_id, "msg-456");
        assert_eq!(input.from, "test@example.com");
        assert_eq!(input.to, vec!["a@b.com", "c@d.com"]);
        assert_eq!(input.subject, Some("Hello".to_string()));
        assert_eq!(input.body, Some("Email body".to_string()));
        assert_eq!(input.body_size, Some(10));
    }

    #[test]
    fn test_hook_input_deserialization_minimal() {
        let json = r#"{
            "hook": "on_mail_from",
            "message_id": "msg-123",
            "from": "sender@test.com",
            "to": [],
            "plugin_config": {}
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.hook, Hook::OnMailFrom);
        assert!(input.subject.is_none());
        assert!(input.body.is_none());
        assert!(input.headers.is_empty());
        assert!(input.metadata.is_empty());
    }

    #[test]
    fn test_hook_result_default() {
        let result: HookResult = Default::default();
        match result {
            HookResult::Continue(metadata) => assert!(metadata.is_empty()),
            _ => panic!("expected Continue variant"),
        }
    }

    #[test]
    fn test_hook_result_variants() {
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), serde_json::json!("value"));

        let continue_result = HookResult::Continue(metadata.clone());
        let reject_result = HookResult::Reject("Rejected".to_string());
        let defer_result = HookResult::Defer("Try later".to_string());

        match continue_result {
            HookResult::Continue(m) => assert_eq!(m.get("key"), Some(&serde_json::json!("value"))),
            _ => panic!("expected Continue"),
        }

        match reject_result {
            HookResult::Reject(msg) => assert_eq!(msg, "Rejected"),
            _ => panic!("expected Reject"),
        }

        match defer_result {
            HookResult::Defer(msg) => assert_eq!(msg, "Try later"),
            _ => panic!("expected Defer"),
        }
    }

    #[test]
    fn test_hook_output_skips_none_message() {
        let output = HookOutput {
            action: HookAction::Continue,
            message: None,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_hook_input_skips_none_fields() {
        let input = HookInput {
            hook: Hook::OnMailFrom,
            message_id: "test".to_string(),
            from: "a@b.com".to_string(),
            to: vec![],
            subject: None,
            headers: HashMap::new(),
            body: None,
            body_size: None,
            plugin_config: serde_json::json!(null),
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("\"subject\""));
        assert!(!json.contains("\"body\""));
        assert!(!json.contains("\"body_size\""));
    }
}
