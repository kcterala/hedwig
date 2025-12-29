use crate::plugins::config::{CfgPlugin, OnError};
use crate::plugins::plugin::Plugin;
use crate::plugins::types::{Hook, HookAction, HookInput, HookResult};
use miette::Result;
use std::collections::HashMap;
use std::sync::Arc;

pub struct PluginManager {
    plugins: Vec<Arc<Plugin>>,
    plugins_by_hook: HashMap<Hook, Vec<usize>>,
}

impl PluginManager {
    pub fn new(plugin_configs: &[CfgPlugin]) -> Result<Self> {
        let enabled_configs: Vec<_> = plugin_configs.iter().filter(|cfg| cfg.enabled).collect();

        if enabled_configs.is_empty() {
            tracing::info!("no plugins enabled");
            return Ok(Self {
                plugins: Vec::new(),
                plugins_by_hook: HashMap::new(),
            });
        }

        let mut plugins = Vec::with_capacity(enabled_configs.len());
        let mut load_errors = Vec::new();

        for config in enabled_configs {
            match Plugin::load(config.clone()) {
                Ok(plugin) => plugins.push(Arc::new(plugin)),
                Err(e) => {
                    tracing::error!(plugin = %config.name, "failed to load plugin: {:#}", e);
                    load_errors.push((config.name.clone(), e));
                }
            }
        }

        if !load_errors.is_empty() {
            let names: Vec<_> = load_errors.iter().map(|(n, _)| n.as_str()).collect();
            tracing::warn!(
                failed_plugins = ?names,
                "some plugins failed to load, continuing with loaded plugins"
            );
        }

        plugins.sort_by_key(|p| p.priority());

        let mut plugins_by_hook: HashMap<Hook, Vec<usize>> = HashMap::new();
        for hook in [
            Hook::OnMailFrom,
            Hook::OnRcptTo,
            Hook::OnData,
            Hook::AfterSend,
            Hook::OnBounce,
        ] {
            let indices: Vec<usize> = plugins
                .iter()
                .enumerate()
                .filter(|(_, p)| p.handles(hook))
                .map(|(i, _)| i)
                .collect();
            plugins_by_hook.insert(hook, indices);
        }

        let hook_counts: Vec<_> = plugins_by_hook
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(h, v)| format!("{:?}={}", h, v.len()))
            .collect();

        tracing::info!(
            loaded = plugins.len(),
            hooks = %hook_counts.join(", "),
            "plugin manager initialized"
        );

        Ok(Self {
            plugins,
            plugins_by_hook,
        })
    }

    pub fn has_plugins_for(&self, hook: Hook) -> bool {
        self.plugins_by_hook
            .get(&hook)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub async fn call_hook(
        &self,
        hook: Hook,
        mut input: HookInput,
        metadata: HashMap<String, serde_json::Value>,
    ) -> HookResult {
        let indices = match self.plugins_by_hook.get(&hook) {
            Some(indices) if !indices.is_empty() => indices.clone(),
            _ => return HookResult::Continue(metadata),
        };

        let plugins: Vec<_> = indices
            .iter()
            .map(|&i| Arc::clone(&self.plugins[i]))
            .collect();

        let result = tokio::task::spawn_blocking(move || {
            let mut merged_metadata = metadata;

            for plugin in plugins {
                input.plugin_config = plugin.plugin_config().clone();
                input.metadata = merged_metadata.clone();

                let result = plugin.call_hook(&input);

                match result {
                    Ok(output) => {
                        merged_metadata.extend(output.metadata);

                        match output.action {
                            HookAction::Continue => continue,
                            HookAction::Reject => {
                                return HookResult::Reject(
                                    output
                                        .message
                                        .unwrap_or_else(|| "Rejected by plugin".into()),
                                );
                            }
                            HookAction::Defer => {
                                return HookResult::Defer(
                                    output
                                        .message
                                        .unwrap_or_else(|| "Deferred by plugin".into()),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(plugin = %plugin.name, error = %e, "plugin error");
                        match plugin.on_error() {
                            OnError::Continue => continue,
                            OnError::Reject => {
                                return HookResult::Reject("Plugin error".into());
                            }
                        }
                    }
                }
            }

            HookResult::Continue(merged_metadata)
        })
        .await;

        result.unwrap_or_else(|e| {
            tracing::error!(error = %e, "plugin execution task panicked");
            HookResult::Continue(HashMap::new())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_plugin_manager() {
        let manager = PluginManager::new(&[]).unwrap();
        assert_eq!(manager.plugin_count(), 0);
        assert!(!manager.has_plugins_for(Hook::OnData));
    }

    #[test]
    fn test_has_plugins_for_empty() {
        let manager = PluginManager::new(&[]).unwrap();
        for hook in [
            Hook::OnMailFrom,
            Hook::OnRcptTo,
            Hook::OnData,
            Hook::AfterSend,
            Hook::OnBounce,
        ] {
            assert!(!manager.has_plugins_for(hook));
        }
    }
}
