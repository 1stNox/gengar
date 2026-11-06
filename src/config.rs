//! User configuration (`~/.config/gengar/config.toml`). Every key is optional.

use crate::scan::Severity;
use serde::Deserialize;
use std::path::PathBuf;

pub const DEFAULT_FEED_URL: &str = "https://security.archlinux.org/all.json";

pub const DEFAULT_CONFIG_TOML: &str = r#"# Gengar configuration. Every key is optional; the values below are the defaults.

# How often to download a fresh vulnerability feed (hours). Between downloads,
# Gengar re-checks against the cached feed whenever installed packages change.
scan_interval_hours = 6

# Minimum severity that counts as "dangerous": turns the tray icon red and shows
# a desktop notification. One of: "low", "medium", "high", "critical".
alert_severity = "high"

# Show a desktop notification when new dangerous vulnerabilities are found.
notify = true

# Treat the feed as outdated (grey icon) when it could not be refreshed for this many days.
stale_after_days = 7

# Vulnerability feed (Arch Linux Security Tracker format). A local file path also works.
feed_url = "https://security.archlinux.org/all.json"

# Acknowledged issues that should not raise alerts: AVG IDs, CVE IDs or package names.
ignore = []
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan_interval_hours: u64,
    pub alert_severity: Severity,
    pub notify: bool,
    pub stale_after_days: u64,
    pub feed_url: String,
    pub ignore: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            scan_interval_hours: 6,
            alert_severity: Severity::High,
            notify: true,
            stale_after_days: 7,
            feed_url: DEFAULT_FEED_URL.to_string(),
            ignore: Vec::new(),
        }
    }
}

impl Config {
    /// Path of the config file (`$GENGAR_CONFIG` overrides it).
    pub fn path() -> PathBuf {
        if let Some(p) = std::env::var_os("GENGAR_CONFIG") {
            return PathBuf::from(p);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gengar")
            .join("config.toml")
    }

    /// Load the config, falling back to defaults when the file is missing.
    /// A broken file is reported on stderr and defaults are used.
    pub fn load() -> Config {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).unwrap_or_else(|e| {
                eprintln!("gengar: ignoring invalid config {}: {e}", path.display());
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.scan_interval_hours = cfg.scan_interval_hours.max(1);
        cfg.stale_after_days = cfg.stale_after_days.max(1);
        Ok(cfg)
    }

    /// Create the config file with commented defaults if it does not exist yet.
    pub fn ensure_file() -> std::io::Result<PathBuf> {
        let path = Self::path();
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, DEFAULT_CONFIG_TOML)?;
        }
        Ok(path)
    }

    pub fn interval_secs(&self) -> u64 {
        self.scan_interval_hours * 3600
    }

    pub fn stale_secs(&self) -> u64 {
        self.stale_after_days * 86400
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_template() {
        let parsed = Config::parse(DEFAULT_CONFIG_TOML).unwrap();
        let def = Config::default();
        assert_eq!(parsed.scan_interval_hours, def.scan_interval_hours);
        assert_eq!(parsed.alert_severity, def.alert_severity);
        assert_eq!(parsed.notify, def.notify);
        assert_eq!(parsed.stale_after_days, def.stale_after_days);
        assert_eq!(parsed.feed_url, def.feed_url);
        assert!(parsed.ignore.is_empty());
    }

    #[test]
    fn partial_config_and_clamping() {
        let cfg = Config::parse("alert_severity = \"Critical\"\nscan_interval_hours = 0\nignore = [\"AVG-1\"]").unwrap();
        assert_eq!(cfg.alert_severity, Severity::Critical);
        assert_eq!(cfg.scan_interval_hours, 1);
        assert_eq!(cfg.ignore, vec!["AVG-1".to_string()]);
        assert!(cfg.notify);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_severity() {
        assert!(Config::parse("scan_intervall = 3").is_err());
        assert!(Config::parse("alert_severity = \"extreme\"").is_err());
    }
}
