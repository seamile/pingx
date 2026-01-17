use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub token: Option<String>,
    pub ipv4_db: Option<String>,
    pub ipv6_db: Option<String>,
}

pub struct ConfigManager {
    config_path: PathBuf,
    pub config: Config,
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let config_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?
            .join(".config")
            .join("pingx");

        if !config_dir.exists() {
            std::fs::create_dir_all(&config_dir).context("Failed to create config directory")?;
        }

        let config_path = config_dir.join("config.toml");
        let config = if config_path.exists() {
            let content =
                std::fs::read_to_string(&config_path).context("Failed to read config.toml")?;
            toml::from_str(&content).context("Failed to parse config.toml")?
        } else {
            Config::default()
        };

        Ok(Self {
            config_path,
            config,
        })
    }

    pub fn save(&self) -> Result<()> {
        let content = toml::to_string(&self.config).context("Failed to serialize config")?;
        std::fs::write(&self.config_path, content).context("Failed to write config.toml")?;
        Ok(())
    }

    pub fn get_config_dir(&self) -> PathBuf {
        self.config_path.parent().unwrap().to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert!(config.token.is_none());
        assert!(config.ipv4_db.is_none());
        assert!(config.ipv6_db.is_none());
    }

    #[test]
    fn test_config_toml_serialization() {
        let config = Config {
            token: Some("test_token".to_string()),
            ipv4_db: Some("v4.bin".to_string()),
            ipv6_db: None,
        };

        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("token = \"test_token\""));
        assert!(toml_str.contains("ipv4_db = \"v4.bin\""));
        assert!(!toml_str.contains("ipv6_db")); // None fields are skipped by default or handled cleanly

        let loaded: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.token, Some("test_token".to_string()));
        assert_eq!(loaded.ipv4_db, Some("v4.bin".to_string()));
        assert_eq!(loaded.ipv6_db, None);
    }
}
