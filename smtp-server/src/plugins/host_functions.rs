//! Host functions exposed to WASM plugins.
//!
//! These functions allow plugins to interact with the host environment,
//! primarily for logging purposes.

use extism::{host_fn, UserData};

/// Context passed to host functions containing plugin metadata.
#[derive(Debug, Clone)]
pub struct LogContext {
    /// Name of the plugin making the call.
    pub plugin_name: String,
}

impl LogContext {
    pub fn new(plugin_name: String) -> Self {
        Self { plugin_name }
    }
}

// Host function for info-level logging.
host_fn!(pub log_info(user_data: LogContext; message: String) {
    let ctx = user_data.get()?;
    let ctx = ctx.lock().unwrap();
    tracing::info!(plugin = %ctx.plugin_name, "{}", message);
    Ok(())
});

// Host function for warning-level logging.
host_fn!(pub log_warn(user_data: LogContext; message: String) {
    let ctx = user_data.get()?;
    let ctx = ctx.lock().unwrap();
    tracing::warn!(plugin = %ctx.plugin_name, "{}", message);
    Ok(())
});

// Host function for error-level logging.
host_fn!(pub log_error(user_data: LogContext; message: String) {
    let ctx = user_data.get()?;
    let ctx = ctx.lock().unwrap();
    tracing::error!(plugin = %ctx.plugin_name, "{}", message);
    Ok(())
});

/// Create the host functions array for plugin initialization.
pub fn create_host_functions(plugin_name: &str) -> Vec<extism::Function> {
    let log_ctx = UserData::new(LogContext::new(plugin_name.to_string()));

    vec![
        extism::Function::new("log_info", [extism::PTR], [], log_ctx.clone(), log_info),
        extism::Function::new("log_warn", [extism::PTR], [], log_ctx.clone(), log_warn),
        extism::Function::new("log_error", [extism::PTR], [], log_ctx, log_error),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_context_creation() {
        let ctx = LogContext::new("test-plugin".to_string());
        assert_eq!(ctx.plugin_name, "test-plugin");
    }

    #[test]
    fn test_create_host_functions() {
        let functions = create_host_functions("test-plugin");
        assert_eq!(functions.len(), 3);
    }
}
