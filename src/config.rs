use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub threshold: u8,
    pub block_on_cve: bool,
    pub auto_install_above_threshold: bool,
    pub ignore: Vec<String>,
    #[serde(default = "default_min_severity")]
    pub min_cve_severity: String,
}

fn default_min_severity() -> String {
    "high".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 70,
            block_on_cve: true,
            auto_install_above_threshold: false,
            ignore: vec![],
            min_cve_severity: "high".to_string(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        match fs::read_to_string("plum.json") {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(_) => Ok(Self::default()),
        }
    }
}
