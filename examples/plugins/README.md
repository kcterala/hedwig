# Hedwig Example Plugins

This directory contains example WASM plugins for Hedwig SMTP server.

## Prerequisites

Install the WASM target for Rust:

```bash
rustup target add wasm32-unknown-unknown
```

## Building Plugins

### Logger Plugin

The logger plugin demonstrates basic hook handling and host function usage.

```bash
cd examples/plugins/logger
cargo build --release --target wasm32-unknown-unknown
```

The compiled plugin will be at:
```
target/wasm32-unknown-unknown/release/hedwig_plugin_logger.wasm
```

## Using Plugins

### 1. Copy the WASM file

```bash
mkdir -p /etc/hedwig/plugins
cp target/wasm32-unknown-unknown/release/hedwig_plugin_logger.wasm /etc/hedwig/plugins/
```

### 2. Configure in config.toml

```toml
[[plugins]]
name = "logger"
path = "/etc/hedwig/plugins/hedwig_plugin_logger.wasm"
enabled = true
on_error = "continue"
priority = 100
hooks = ["on_mail_from", "on_rcpt_to", "on_data", "after_send", "on_bounce"]

[plugins.config]
log_headers = false
log_body = false
```

### 3. Restart Hedwig

```bash
systemctl restart hedwig
# or
./hedwig
```

## Plugin Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Unique identifier for the plugin |
| `path` | string | required | Path to the .wasm file |
| `enabled` | bool | `true` | Whether the plugin is active |
| `on_error` | string | `"continue"` | Error handling: `"continue"` or `"reject"` |
| `priority` | int | `50` | Execution order (lower runs first) |
| `hooks` | array | required | List of hooks to subscribe to |
| `config` | table | `{}` | Plugin-specific configuration |

## Available Hooks

| Hook | Trigger | Available Data |
|------|---------|----------------|
| `on_mail_from` | MAIL FROM command | `from`, `message_id` |
| `on_rcpt_to` | RCPT TO command | `from`, `to`, `message_id` |
| `on_data` | Email body received | Full email: `from`, `to`, `subject`, `headers`, `body`, `body_size` |
| `after_send` | Successful delivery | Full email + delivery metadata |
| `on_bounce` | Email bounced | Full email + bounce info |

## Writing Your Own Plugin

See [docs/PLUGINS.md](../../docs/PLUGINS.md) for the complete plugin development guide.

### Quick Start Template

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
    plugin_config: serde_json::Value,
    metadata: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct HookOutput {
    action: String,
    message: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

#[host_fn]
extern "ExtismHost" {
    fn log_info(message: &str);
    fn log_warn(message: &str);
    fn log_error(message: &str);
}

#[plugin_fn]
pub fn on_data(input: String) -> FnResult<String> {
    let input: HookInput = serde_json::from_str(&input)?;
    
    unsafe {
        log_info(&format!("Processing email: {}", input.message_id))?;
    }
    
    let output = HookOutput {
        action: "continue".to_string(),
        message: None,
        metadata: HashMap::new(),
    };
    
    Ok(serde_json::to_string(&output)?)
}
```

## Cargo.toml Template

```toml
[package]
name = "my-hedwig-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
extism-pdk = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```
