use crate::plugins::config::{CfgPlugin, OnError};
use crate::plugins::host_functions::create_host_functions;
use crate::plugins::types::{Hook, HookInput, HookOutput};
use miette::Result;
use std::collections::HashSet;
use std::sync::Mutex;

pub struct Plugin {
    pub name: String,
    pub config: CfgPlugin,
    instance: Mutex<extism::Plugin>,
    hooks: HashSet<Hook>,
}

impl Plugin {
    pub fn load(config: CfgPlugin) -> Result<Self> {
        let wasm = extism::Wasm::file(&config.path);
        let manifest = extism::Manifest::new([wasm]);

        let host_functions = create_host_functions(&config.name);

        let instance = extism::Plugin::new(&manifest, host_functions, true).map_err(|e| {
            miette::miette!(
                "failed to load plugin '{}' from '{}': {}",
                config.name,
                config.path,
                e
            )
        })?;

        let hooks: HashSet<Hook> = config
            .hooks
            .iter()
            .filter_map(|s| Hook::from_str(s))
            .collect();

        if hooks.is_empty() {
            tracing::warn!(
                plugin = %config.name,
                "plugin has no valid hooks configured"
            );
        }

        tracing::info!(
            plugin = %config.name,
            path = %config.path,
            hooks = ?hooks,
            "loaded plugin"
        );

        Ok(Self {
            name: config.name.clone(),
            config,
            instance: Mutex::new(instance),
            hooks,
        })
    }

    pub fn call_hook(&self, input: &HookInput) -> Result<HookOutput> {
        let input_json = serde_json::to_vec(input)
            .map_err(|e| miette::miette!("failed to serialize hook input: {}", e))?;

        let function_name = input.hook.function_name();

        let mut instance = self
            .instance
            .lock()
            .map_err(|_| miette::miette!("plugin instance lock poisoned for '{}'", self.name))?;

        let has_function = instance.function_exists(function_name);
        if !has_function {
            tracing::debug!(
                plugin = %self.name,
                function = %function_name,
                "plugin does not export this function, skipping"
            );
            return Ok(HookOutput::default());
        }

        let output_bytes = instance
            .call::<Vec<u8>, Vec<u8>>(function_name, input_json)
            .map_err(|e| {
                miette::miette!(
                    "plugin '{}' failed to execute '{}': {}",
                    self.name,
                    function_name,
                    e
                )
            })?;

        let output: HookOutput = serde_json::from_slice(&output_bytes).map_err(|e| {
            miette::miette!(
                "plugin '{}' returned invalid JSON from '{}': {}",
                self.name,
                function_name,
                e
            )
        })?;

        Ok(output)
    }

    pub fn handles(&self, hook: Hook) -> bool {
        self.hooks.contains(&hook)
    }

    pub fn on_error(&self) -> &OnError {
        &self.config.on_error
    }

    pub fn priority(&self) -> i32 {
        self.config.priority
    }

    pub fn plugin_config(&self) -> &serde_json::Value {
        &self.config.config
    }
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.name)
            .field("hooks", &self.hooks)
            .field("priority", &self.config.priority)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_handles_hook() {
        let hooks: HashSet<Hook> = vec![Hook::OnData, Hook::AfterSend].into_iter().collect();

        assert!(hooks.contains(&Hook::OnData));
        assert!(hooks.contains(&Hook::AfterSend));
        assert!(!hooks.contains(&Hook::OnMailFrom));
    }
}
