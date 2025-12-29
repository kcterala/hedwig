//! WASM Plugin system for Hedwig using Extism.
//!
//! This module provides a plugin system that allows users to extend the email lifecycle
//! with custom logic via WASM plugins.

mod config;
mod host_functions;
mod manager;
mod plugin;
mod types;

pub use config::{CfgPlugin, OnError};
pub use manager::PluginManager;
pub use types::{Hook, HookAction, HookInput, HookOutput, HookResult};
