# Domain Filter Plugin for Hedwig

A WebAssembly (WASM) plugin for Hedwig SMTP server that provides domain-based email filtering. This plugin allows you to block or allow email based on sender and recipient domains.

## Overview

The Domain Filter plugin intercepts email delivery at the `on_mail_from` and `on_rcpt_to` hooks to validate email domains against configurable blocklists or allowlists. It uses the Extism framework for WASM execution and integrates seamlessly with Hedwig's plugin system.

### Features

- **Dual Filtering Modes**: Supports both blocklist and allowlist modes
- **Multiple Hook Support**: Validates both sender (`on_mail_from`) and recipient (`on_rcpt_to`) domains
- **Flexible Configuration**: Configure blocked/allowed domains via Hedwig's plugin config
- **Comprehensive Logging**: Uses host functions for detailed logging of filter decisions
- **Metadata Tracking**: Returns metadata about domain checks for monitoring and debugging

### How It Works

1. **Blocklist Mode** (default): Rejects emails from or to domains listed in `blocked_domains`
2. **Allowlist Mode**: Only accepts emails from or to domains listed in `allowed_domains`
3. The plugin checks sender domains in the `on_mail_from` hook
4. It checks recipient domains in the `on_rcpt_to` hook
5. Returns `reject` action if domain doesn't pass filter, `continue` otherwise

## Prerequisites

- **Go 1.21 or later**: Required for compilation
- **TinyGo 0.28.0 or later** (recommended): For smaller WASM binary size
  - Alternative: Standard Go compiler with `GOOS=js GOARCH=wasm`
- **Hedwig SMTP Server**: With plugin system enabled

## Installation

### 1. Clone or Navigate to Plugin Directory

```bash
cd examples/plugins/domain-filter
```

### 2. Download Dependencies

```bash
go mod tidy
```

This will download the Extism Go PDK dependency.

### 3. Build the WASM Module

#### Option A: Using TinyGo (Recommended)

TinyGo produces significantly smaller WASM binaries (typically 50-200KB vs 2-3MB with standard Go):

```bash
tinygo build -o domain_filter.wasm -target wasm main.go
```

**Installing TinyGo:**

- **macOS**: `brew install tinygo`
- **Linux**: Follow instructions at https://tinygo.org/getting-started/install/linux/
- **Windows**: Download from https://github.com/tinygo-org/tinygo/releases

#### Option B: Using Standard Go Compiler

If you don't have TinyGo installed, you can use the standard Go compiler:

```bash
GOOS=js GOARCH=wasm go build -o domain_filter.wasm main.go
```

Note: This produces larger binaries but works without additional tooling.

### 4. Verify the Build

Check that the WASM file was created:

```bash
ls -lh domain_filter.wasm
```

Expected output:

- TinyGo build: ~50-200KB
- Standard Go build: ~2-3MB

## Configuration

### Hedwig Configuration

Add the plugin to your Hedwig `config.toml`:

```toml
[[plugins]]
name = "domain-filter"
path = "/path/to/domain_filter.wasm"
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
# Blocklist mode: Reject emails from/to these domains
mode = "blocklist"
blocked_domains = [
    "spam.com",
    "malicious-domain.org",
    "suspicious.net"
]
# Optional: allowed_domains is ignored in blocklist mode
allowed_domains = []
```

### Allowlist Mode Configuration

```toml
[[plugins]]
name = "domain-filter"
path = "/path/to/domain_filter.wasm"
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
# Allowlist mode: Only accept emails from/to these domains
mode = "allowlist"
allowed_domains = [
    "trusted-company.com",
    "partner.org",
    "internal.net"
]
# Optional: blocked_domains is ignored in allowlist mode
blocked_domains = []
```

### Configuration Options

| Option            | Type   | Description                                                          |
| ----------------- | ------ | -------------------------------------------------------------------- |
| `mode`            | string | Filter mode: `"blocklist"` or `"allowlist"` (default: `"blocklist"`) |
| `blocked_domains` | array  | List of domains to block (used in blocklist mode)                    |
| `allowed_domains` | array  | List of domains to allow (used in allowlist mode)                    |

## Usage

### Example 1: Blocking Spam Domains

```toml
[[plugins]]
name = "domain-filter"
path = "/path/to/domain_filter.wasm"
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
mode = "blocklist"
blocked_domains = [
    "spam-source.com",
    "phishing-site.net",
    "malicious-domain.org"
]
```

When an email arrives from `user@spam-source.com`, the plugin will:

1. Extract the domain `spam-source.com`
2. Check against the blocklist
3. Return `reject` action with message: "Domain 'spam-source.com' is not allowed: Domain is blocked"
4. Hedwig will reject the email with SMTP 5xx error

### Example 2: Allowing Only Trusted Domains

```toml
[[plugins]]
name = "domain-filter"
path = "/path/to/domain_filter.wasm"
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
mode = "allowlist"
allowed_domains = [
    "mycompany.com",
    "trusted-partner.com"
]
```

When an email arrives from `user@unknown-domain.com`, the plugin will:

1. Extract the domain `unknown-domain.com`
2. Check against the allowlist
3. Return `reject` action with message: "Domain 'unknown-domain.com' is not allowed: Domain not in allowlist"
4. Hedwig will reject the email with SMTP 5xx error

### Example 3: Mixed Configuration

You can combine multiple plugins for more complex filtering:

```toml
# First, block known spam domains
[[plugins]]
name = "domain-filter-blocklist"
path = "/path/to/domain_filter.wasm"
hooks = ["on_mail_from", "on_rcpt_to"]

[plugins.config]
mode = "blocklist"
blocked_domains = ["spam.com", "malicious.org"]

# Then, allow only specific domains for internal mail
[[plugins]]
name = "domain-filter-allowlist"
path = "/path/to/domain_filter.wasm"
hooks = ["on_rcpt_to"]

[plugins.config]
mode = "allowlist"
allowed_domains = ["internal.company.com"]
```

## Testing

### Manual Testing with Hedwig

1. Build the WASM module
2. Configure Hedwig with the plugin (see Configuration section)
3. Start Hedwig: `cargo run`
4. Send test emails using a mail client or `telnet`:

```bash
# Test with blocked domain
telnet localhost 2525
# SMTP session:
# EHLO test.com
# MAIL FROM:<user@spam.com>
# RCPT TO:<recipient@trusted.com>
# Expected: 550 rejection

# Test with allowed domain
telnet localhost 2525
# SMTP session:
# EHLO test.com
# MAIL FROM:<user@trusted.com>
# RCPT TO:<recipient@trusted.com>
# Expected: 250 accepted
```

### Unit Testing

The plugin includes comprehensive error handling and logging. Check Hedwig's logs for detailed information:

```
[INFO] on_mail_from hook triggered for: user@spam.com
[INFO] Checking domain 'spam.com': Domain is blocked
[WARN] Domain 'spam.com' rejected: Domain is blocked
```

## Plugin API

### Input Structure

The plugin receives JSON input with the following structure:

```json
{
  "hook": "on_mail_from",
  "message_id": "unique-message-id",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "plugin_config": {
    "blocked_domains": ["spam.com"],
    "allowed_domains": ["trusted.com"],
    "mode": "blocklist"
  },
  "metadata": {}
}
```

### Output Structure

The plugin returns JSON output with the following structure:

```json
{
  "action": "continue",
  "message": "Domain 'example.com' passed filter",
  "metadata": {
    "domain_checked": "example.com",
    "filter_mode": "blocklist"
  }
}
```

### Action Types

- `continue`: Allow email to proceed to the next stage
- `reject`: Permanently reject with SMTP 5xx error
- `defer`: Temporarily reject with SMTP 4xx error (not used by this plugin)

### Exported Functions

- `on_mail_from`: Validates the sender's email domain
- `on_rcpt_to`: Validates all recipient email domains

### Host Functions Used

- `log_info`: Logs informational messages
- `log_warn`: Logs warning messages
- `log_error`: Logs error messages

## Troubleshooting

### Plugin Not Loading

**Problem**: Hedwig fails to load the plugin

**Solutions**:

- Verify the WASM file path is correct
- Check file permissions: `ls -la domain_filter.wasm`
- Ensure the WASM file is not corrupted: `file domain_filter.wasm`

### Emails Not Being Filtered

**Problem**: Emails from blocked domains are still accepted

**Solutions**:

- Verify the plugin is configured in `config.toml`
- Check that hooks include both `on_mail_from` and `on_rcpt_to`
- Verify the `mode` setting matches your intended behavior
- Check Hedwig logs for plugin execution messages

### Build Errors

**Problem**: `go build` fails with import errors

**Solutions**:

```bash
# Ensure dependencies are downloaded
go mod tidy

# Verify Go version
go version  # Should be 1.21 or later

# If using TinyGo, verify installation
tinygo version
```

### Large WASM File Size

**Problem**: Standard Go build produces very large WASM file

**Solutions**:

- Use TinyGo instead: `tinygo build -o domain_filter.wasm -target wasm main.go`
- TinyGo produces 10-50x smaller binaries

## Performance Considerations

- **TinyGo Build**: Recommended for production (faster load times, lower memory usage)
- **Domain Matching**: Uses case-insensitive comparison for reliability
- **Early Rejection**: Rejects emails as early as possible (during SMTP transaction)
- **Minimal Overhead**: Simple string matching with O(n) complexity per check

## Security Considerations

- **Case Sensitivity**: Domain matching is case-insensitive to prevent bypasses
- **Empty Allowlist**: In allowlist mode, an empty list blocks all domains
- **Default Behavior**: On configuration errors, plugin defaults to `continue` (fail-open)
- **Logging**: All filter decisions are logged for audit trails

## License

This plugin is part of the Hedwig project. See the main Hedwig LICENSE file for details.

## Contributing

To improve this plugin:

1. Test your changes with both blocklist and allowlist modes
2. Ensure compatibility with Hedwig's plugin system
3. Update this README with any new features or configuration options
4. Submit a pull request to the Hedwig repository

## Related Documentation

- [Hedwig Plugin System](../../docs/PLUGINS.md)
- [Hedwig Configuration Guide](../../docs/CONFIGURATION.md)
- [Extism Documentation](https://extism.org/docs/)
- [Extism Go PDK](https://github.com/extism/go-pdk)
