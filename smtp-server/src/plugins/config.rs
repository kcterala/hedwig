use serde::Deserialize;

/// Behavior when a plugin encounters an error.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Continue to next plugin (fail-open).
    #[default]
    Continue,
    /// Reject the email (fail-closed).
    Reject,
}

/// Configuration for a single WASM plugin.
#[derive(Debug, Deserialize, Clone)]
pub struct CfgPlugin {
    /// Human-readable name for the plugin.
    pub name: String,
    /// Path to the WASM file.
    pub path: String,
    /// Whether the plugin is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Behavior when the plugin returns an error.
    #[serde(default)]
    pub on_error: OnError,
    /// Priority for plugin execution order (lower runs first).
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Hooks this plugin handles.
    pub hooks: Vec<String>,
    /// Plugin-specific configuration passed to the plugin.
    #[serde(default)]
    pub config: serde_json::Value,
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i32 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_on_error_default() {
        let on_error: OnError = Default::default();
        assert_eq!(on_error, OnError::Continue);
    }

    #[test]
    fn test_cfg_plugin_deserialization() {
        let toml = r#"
            name = "test-plugin"
            path = "/path/to/plugin.wasm"
            hooks = ["on_data", "after_send"]

            [config]
            threshold = 5.0
        "#;

        let plugin: CfgPlugin = toml::from_str(toml).unwrap();
        assert_eq!(plugin.name, "test-plugin");
        assert_eq!(plugin.path, "/path/to/plugin.wasm");
        assert!(plugin.enabled); // default
        assert_eq!(plugin.on_error, OnError::Continue); // default
        assert_eq!(plugin.priority, 50); // default
        assert_eq!(plugin.hooks, vec!["on_data", "after_send"]);
        assert_eq!(plugin.config["threshold"], 5.0);
    }

    #[test]
    fn test_cfg_plugin_with_all_fields() {
        let toml = r#"
            name = "spam-filter"
            path = "/etc/hedwig/plugins/spam.wasm"
            enabled = false
            on_error = "reject"
            priority = 10
            hooks = ["on_data"]

            [config]
            api_key = "secret"
        "#;

        let plugin: CfgPlugin = toml::from_str(toml).unwrap();
        assert_eq!(plugin.name, "spam-filter");
        assert!(!plugin.enabled);
        assert_eq!(plugin.on_error, OnError::Reject);
        assert_eq!(plugin.priority, 10);
    }
}
