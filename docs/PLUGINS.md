# Plugin Development Guide

Hedwig supports WASM plugins via [Extism](https://extism.org/) for extending email processing. Plugins can inspect and modify email flow at various points in the lifecycle.

## Overview

Plugins are WebAssembly modules that:

- Subscribe to specific hooks in the email lifecycle
- Receive JSON input with email context
- Return JSON output with an action and optional metadata
- Can use host functions for logging

## Quick Start

### 1. Create a new Rust project

```bash
cargo new --lib my-plugin
cd my-plugin
```

### 2. Configure Cargo.toml

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### 3. Implement hooks in src/lib.rs

```rust
use extism_pdk::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct HookInput {
    hook: String,
    message_id: String,
    from: String,
    to: Vec<String>,
    subject: Option<String>,
    headers: HashMap<String, String>,
    body: Option<String>,
    body_size: Option<usize>,
    plugin_config: serde_json::Value,
    metadata: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct HookOutput {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

#[plugin_fn]
pub fn on_data(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    // Your logic here

    let output = HookOutput {
        action: "continue".to_string(),
        message: None,
        metadata: HashMap::new(),
    };

    Ok(serde_json::to_string(&output)?)
}
```

### 4. Build the plugin

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Output: `target/wasm32-unknown-unknown/release/my_plugin.wasm`

### 5. Configure in Hedwig

```toml
[[plugins]]
name = "my-plugin"
path = "/path/to/my_plugin.wasm"
hooks = ["on_data"]
```

## Hooks

### Hook Lifecycle

```
Client connects
    │
    ├── MAIL FROM ──► on_mail_from
    │
    ├── RCPT TO ────► on_rcpt_to (called per recipient)
    │
    ├── DATA ───────► on_data
    │
    └── (queued for delivery)
            │
            ├── Success ──► after_send
            │
            └── Failure ──► on_bounce
```

### on_mail_from

Called when the MAIL FROM command is received.

**Use cases:**

- Sender validation
- Reputation checking
- Early rejection of known bad senders

**Available fields:**

- `message_id` - Unique message identifier
- `from` - Sender email address
- `plugin_config` - Your plugin's configuration
- `metadata` - Metadata from previous plugins

### on_rcpt_to

Called for each RCPT TO command.

**Use cases:**

- Recipient validation
- Routing decisions
- Per-recipient filtering

**Available fields:**

- All `on_mail_from` fields
- `to` - Array of recipient addresses (current recipient)

### on_data

Called after the email body is received.

**Use cases:**

- Spam filtering
- Content inspection
- Header analysis
- Virus scanning (via external API)

**Available fields:**

- All previous fields
- `subject` - Email subject
- `headers` - All email headers
- `body` - Email body (if configured)
- `body_size` - Size in bytes

### after_send

Called after successful email delivery.

**Use cases:**

- Audit logging
- Analytics
- Webhooks to external services
- Success notifications

**Available fields:**

- All `on_data` fields
- Delivery metadata from the send operation

### on_bounce

Called when an email permanently fails delivery.

**Use cases:**

- Suppression list management
- Alerting
- Bounce analytics
- Notifying original sender

**Available fields:**

- All `on_data` fields
- Bounce reason in metadata

## Input Schema

Full JSON structure passed to hooks:

```json
{
  "hook": "on_data",
  "message_id": "01JGXYZ123ABC",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "subject": "Hello World",
  "headers": {
    "From": "Sender <sender@example.com>",
    "To": "recipient@example.com",
    "Subject": "Hello World",
    "Date": "Mon, 1 Jan 2025 12:00:00 +0000",
    "Message-ID": "<unique-id@example.com>"
  },
  "body": "Email body content...",
  "body_size": 1234,
  "plugin_config": {
    "custom_setting": "value"
  },
  "metadata": {
    "previous_plugin_data": "value"
  }
}
```

Note: Not all fields are available for all hooks. Early hooks like `on_mail_from` only have basic fields.

## Output Schema

Response format from plugins:

```json
{
  "action": "continue",
  "message": "Optional message for reject/defer",
  "metadata": {
    "my_data": "passed to next plugin"
  }
}
```

### Actions

| Action     | Effect                                   |
| ---------- | ---------------------------------------- |
| `continue` | Proceed to next plugin or step           |
| `reject`   | Permanently reject the email             |
| `defer`    | Temporarily reject (client should retry) |

### Examples

**Continue processing:**

```json
{
  "action": "continue",
  "metadata": { "spam_score": 2.5 }
}
```

**Reject spam:**

```json
{
  "action": "reject",
  "message": "550 Message rejected as spam"
}
```

**Temporary failure:**

```json
{
  "action": "defer",
  "message": "421 Service temporarily unavailable"
}
```

## Host Functions

Plugins can call these functions provided by Hedwig:

### Logging

```rust
#[host_fn]
extern "ExtismHost" {
    fn log_info(message: &str);
    fn log_warn(message: &str);
    fn log_error(message: &str);
}
```

Usage:

```rust
unsafe {
    log_info("Processing email")?;
    log_warn("Suspicious content detected")?;
    log_error("Failed to process")?;
}
```

Logs appear in Hedwig's output with your plugin name:

```
INFO hedwig: [my-plugin] Processing email
WARN hedwig: [my-plugin] Suspicious content detected
```

## Configuration

### Plugin Configuration

```toml
[[plugins]]
name = "spam-filter"
path = "/etc/hedwig/plugins/spam.wasm"
enabled = true
on_error = "continue"
priority = 10
hooks = ["on_data"]

[plugins.config]
threshold = 5.0
api_key = "xxx"
custom_list = ["item1", "item2"]
```

### Configuration Options

| Option     | Type   | Default      | Description              |
| ---------- | ------ | ------------ | ------------------------ |
| `name`     | string | required     | Unique plugin identifier |
| `path`     | string | required     | Path to .wasm file       |
| `enabled`  | bool   | `true`       | Enable/disable plugin    |
| `on_error` | string | `"continue"` | Error handling mode      |
| `priority` | int    | `50`         | Execution order          |
| `hooks`    | array  | required     | Subscribed hooks         |
| `config`   | table  | `{}`         | Plugin-specific config   |

### Priority

Plugins run in priority order (lower numbers first):

```toml
[[plugins]]
name = "spam-filter"
priority = 10  # Runs first

[[plugins]]
name = "logger"
priority = 100  # Runs last
```

### Error Handling

The `on_error` setting controls behavior when a plugin fails:

- `"continue"` (default): Log the error and continue with next plugin
- `"reject"`: Reject the email if plugin fails

## Metadata Passing

Plugins can pass data to subsequent plugins via metadata:

**Plugin A (priority 10):**

```rust
let mut metadata = HashMap::new();
metadata.insert("spam_score".to_string(), json!(2.5));
metadata.insert("checked_at".to_string(), json!("2025-01-01T12:00:00Z"));

HookOutput {
    action: "continue".to_string(),
    message: None,
    metadata,
}
```

**Plugin B (priority 20):**

```rust
// Access metadata from Plugin A
if let Some(score) = input.metadata.get("spam_score") {
    let score: f64 = serde_json::from_value(score.clone())?;
    if score > 5.0 {
        return Ok(serde_json::to_string(&HookOutput {
            action: "reject".to_string(),
            message: Some("Spam detected".to_string()),
            metadata: HashMap::new(),
        })?);
    }
}
```

Metadata also persists across hooks for the same email, so `on_data` metadata is available in `after_send`.

## Example Plugins

### Spam Filter

```rust
use extism_pdk::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct HookInput {
    from: String,
    subject: Option<String>,
    body: Option<String>,
    plugin_config: SpamConfig,
    #[serde(default)]
    metadata: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct SpamConfig {
    #[serde(default = "default_threshold")]
    threshold: f64,
    #[serde(default)]
    blocked_domains: Vec<String>,
}

fn default_threshold() -> f64 { 5.0 }

#[derive(Serialize)]
struct HookOutput {
    action: String,
    message: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

#[plugin_fn]
pub fn on_data(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;
    let mut score = 0.0;

    // Check blocked domains
    let from_domain = input.from.split('@').last().unwrap_or("");
    if input.plugin_config.blocked_domains.contains(&from_domain.to_string()) {
        return Ok(serde_json::to_string(&HookOutput {
            action: "reject".to_string(),
            message: Some("550 Sender domain blocked".to_string()),
            metadata: HashMap::new(),
        })?);
    }

    // Simple spam heuristics
    if let Some(subject) = &input.subject {
        let subject_lower = subject.to_lowercase();
        if subject_lower.contains("viagra") || subject_lower.contains("lottery") {
            score += 3.0;
        }
        if subject.chars().filter(|c| *c == '!').count() > 3 {
            score += 1.0;
        }
    }

    // Add score to metadata for other plugins
    let mut metadata = HashMap::new();
    metadata.insert("spam_score".to_string(), serde_json::json!(score));

    if score >= input.plugin_config.threshold {
        Ok(serde_json::to_string(&HookOutput {
            action: "reject".to_string(),
            message: Some(format!("550 Message rejected (score: {})", score)),
            metadata,
        })?)
    } else {
        Ok(serde_json::to_string(&HookOutput {
            action: "continue".to_string(),
            message: None,
            metadata,
        })?)
    }
}
```

Configuration:

```toml
[[plugins]]
name = "spam-filter"
path = "/etc/hedwig/plugins/spam.wasm"
priority = 10
hooks = ["on_data"]

[plugins.config]
threshold = 5.0
blocked_domains = ["spam.com", "malware.net"]
```

### Webhook Notifier

```rust
use extism_pdk::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
struct HookInput {
    message_id: String,
    from: String,
    to: Vec<String>,
    plugin_config: WebhookConfig,
}

#[derive(Deserialize)]
struct WebhookConfig {
    url: String,
}

#[derive(Serialize)]
struct HookOutput {
    action: String,
    message: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct WebhookPayload {
    event: String,
    message_id: String,
    from: String,
    to: Vec<String>,
}

#[host_fn]
extern "ExtismHost" {
    fn log_info(message: &str);
    fn log_error(message: &str);
}

#[plugin_fn]
pub fn after_send(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;

    // Note: WASM can't make HTTP calls directly
    // Log the intent - in production you'd use a host function
    unsafe {
        log_info(&format!(
            "Would POST to {}: message_id={}, from={}, to={:?}",
            input.plugin_config.url,
            input.message_id,
            input.from,
            input.to
        ))?;
    }

    Ok(serde_json::to_string(&HookOutput {
        action: "continue".to_string(),
        message: None,
        metadata: HashMap::new(),
    })?)
}
```

### Go Plugin Example: Domain Filter

This example demonstrates Go WASM plugin development with Extism, implementing domain-based email filtering with support for blocklist and allowlist modes.

#### Features

- Supports blocklist and allowlist filtering modes
- Filters based on sender (on_mail_from) and recipient (on_rcpt_to) domains
- Uses Extism Go PDK for WASM execution
- Calls host functions for logging
- Returns metadata for monitoring

#### Location

- Path: `examples/plugins/domain-filter/`
- Files: `main.go`, `go.mod`, `README.md`, `config.example.toml`

#### Building the Plugin

```bash
cd examples/plugins/domain-filter
go mod tidy

# Using TinyGo (recommended for smaller size):
tinygo build -o domain_filter.wasm -target wasm main.go

# Using standard Go:
GOOS=js GOARCH=wasm go build -o domain_filter.wasm main.go
```

#### Configuration Example

```toml
[[plugins]]
name = "domain-filter"
path = "examples/plugins/domain-filter/domain_filter.wasm"
priority = 10
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
blocked_domains = ["spam.com", "malware.net"]
mode = "blocklist"
```

#### Key Implementation Details

- Uses Extism Go PDK (github.com/extism/go-pdk)
- Exports `on_mail_from` and `on_rcpt_to` functions
- Parses JSON input and returns JSON output
- Implements domain extraction and matching logic
- Handles errors with fail-open default behavior

#### For More Information

- See [`examples/plugins/domain-filter/README.md`](../examples/plugins/domain-filter/README.md) for detailed documentation
- Extism Go PDK documentation: https://pkg.go.dev/github.com/extism/go-pdk

## Testing Plugins

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spam_detection() {
        let input = r#"{
            "hook": "on_data",
            "message_id": "test-123",
            "from": "spammer@spam.com",
            "to": ["victim@example.com"],
            "subject": "WIN LOTTERY!!!",
            "plugin_config": {
                "threshold": 3.0,
                "blocked_domains": ["spam.com"]
            },
            "metadata": {}
        }"#;

        // Test your logic
        let input: HookInput = serde_json::from_str(input).unwrap();
        assert!(input.plugin_config.blocked_domains.contains(&"spam.com".to_string()));
    }
}
```

### Integration Testing

1. Build your plugin
2. Configure Hedwig with `HEDWIG_LOG_LEVEL=debug`
3. Send test emails via SMTP
4. Check logs for plugin output

## Best Practices

1. **Fail safely**: Use `on_error = "continue"` unless rejection is critical
2. **Be fast**: Plugins run synchronously; avoid expensive operations
3. **Log judiciously**: Use host functions to log important events
4. **Pass metadata**: Share computed data with other plugins
5. **Handle missing fields**: Not all hooks have all fields
6. **Version your plugins**: Include version in plugin name for upgrades

## Limitations

- **No network access**: WASM plugins cannot make HTTP calls directly
- **No filesystem access**: Plugins cannot read/write files
- **Synchronous execution**: Plugins block the email flow
- **No hot reload**: Restart Hedwig to reload plugins
- **Memory limits**: Extism enforces memory limits on plugins

## Troubleshooting

### Plugin not loading

Check the logs:

```bash
HEDWIG_LOG_LEVEL=debug ./hedwig
```

Common issues:

- Wrong path in config
- Missing WASM file
- Invalid WASM binary (compile with `--target wasm32-unknown-unknown`)

### Hook not being called

Verify:

- Hook name in config matches function name exactly
- Plugin is `enabled = true`
- Hook is in the `hooks` array

### Plugin errors

With `on_error = "continue"`, errors are logged but don't stop processing:

```
ERROR hedwig: [my-plugin] Plugin execution failed: ...
```

Set `HEDWIG_LOG_LEVEL=debug` for more details.
