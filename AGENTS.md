# Repository Guidelines

## 1. Build, Test & Lint Commands

### Common Commands
- **Run Dev Server**: `just run` (wraps `cargo run`)
- **Run Release**: `just run-release`
- **Build Release**: `just build` (wraps `cargo build`)
- **Test All**: `just test` (wraps `cargo test`)
- **Lint**: `cargo clippy --workspace --all-targets`
- **Format**: `cargo fmt`

### Advanced Testing (Crucial for Agents)
- **Run Single Test**:
  ```bash
  cargo test test_name_here
  ```
- **Run Single Test in Specific Crate**:
  ```bash
  cargo test -p smtp-server -- test_name_here
  ```
- **Run with Output**:
  ```bash
  cargo test test_name_here -- --nocapture
  ```
- **Run Integration Tests Only**:
  ```bash
  cargo test --test integration_test_name
  ```

## 2. Repository Structure

- **Workspace Root**: `Cargo.toml` defines workspace members.
- **`smtp/` (Library)**:
  - Protocol parsers (`src/parser.rs`)
  - Shared types (`src/lib.rs`)
  - Pure Rust, minimal dependencies.
  - Uses `thiserror` for library errors.
- **`smtp-server/` (Application)**:
  - Main binary entry (`src/main.rs`)
  - Configuration (`src/config.rs`)
  - SMTP Logic (`src/callbacks.rs`)
  - Storage backends (`src/storage/`)
  - Worker queues (`src/worker/`)
  - Uses `miette` for application errors.
  - Uses `tokio` for async runtime.

## 3. Code Style & Conventions

### Formatting & Imports
- **Standard Rust**: 4-space indentation.
- **Import Order**:
  1. `std` / `core`
  2. External crates (`tokio`, `tracing`, `miette`)
  3. Internal modules (`crate::config`, `super::*`)
- **Grouping**: Group imports from the same crate (e.g., `use tokio::net::{TcpListener, TcpStream};`).

### Naming
- **Functions/Variables**: `snake_case`
- **Types/Traits**: `UpperCamelCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Files**: `snake_case.rs` matches module name.

### Error Handling
- **Application (`smtp-server`)**:
  - Return `miette::Result<T>`.
  - Use `IntoDiagnostic` and `WrapErr` (or `Context`) for context.
  - Example: `.into_diagnostic().wrap_err("failed to bind port")?`
- **Library (`smtp`)**:
  - Define custom enums with `thiserror`.
  - Do NOT use `miette` or `anyhow` in the library public API.

### Async & Concurrency
- Use `tokio` for all async operations.
- Use `#[async_trait]` for traits requiring async methods (e.g., `SmtpCallbacks`, `Storage`).
- Spawning: Use `tokio::spawn` for background tasks. Track handles if graceful shutdown is needed.
- Channels: Use `async_channel` for worker queues.

### Logging
- Use `tracing` crate (`info!`, `warn!`, `error!`, `debug!`).
- Do NOT use `println!` or `eprintln!` in production code (except early startup/CLI).
- Structured logging is preferred: `info!(user = %username, "login successful");`

## 4. Testing Guidelines

- **Location**: Co-locate tests with code in `#[cfg(test)] mod tests { ... }` blocks at the bottom of the file.
- **Async Tests**: Use `#[tokio::test]`.
- **Mocking**: Use struct-based mocks (like `MockStorage` in `callbacks.rs`) rather than heavy mocking frameworks if simple traits suffice.
- **Fixtures**: Keep test logic self-contained or use helper functions within the `tests` module.

## 5. Development Workflow

1. **Analysis**: Before implementing, understand the module role (`smtp` vs `smtp-server`).
2. **Implementation**:
   - Follow existing patterns.
   - If adding a new feature, update `config.rs` and `config.example.toml` if needed.
3. **Verification**:
   - Run related tests: `cargo test -p <crate> -- <module_name>`
   - Check linting: `cargo clippy`
   - Ensure clean build: `cargo build`
4. **Docs**: Update module-level docs if architectural changes are made.

## 6. Critical constraints
- **Never** commit secrets or keys.
- **Never** suppress types with `unsafe` unless absolutely necessary and documented.
- **Never** leave `todo!()` macros in production paths.
