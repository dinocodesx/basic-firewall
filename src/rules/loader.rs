use crate::rules::types::Config;
use anyhow::Result;
use std::fs;

/// Loads the firewall configuration from a TOML file.
pub fn load_config(path: &str) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
