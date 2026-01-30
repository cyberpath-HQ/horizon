//! # Logging Configuration
//!
//! Configuration for the logging subsystem.
//! Supports environment variables and programmatic configuration.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, Registry};

/// Logging configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    #[serde(default = "default_level")]
    pub level: String,

    /// Output format (json, pretty, compact)
    #[serde(default = "default_format")]
    pub format: String,

    /// Optional log file path
    #[serde(default = "default_log_file")]
    pub log_file: Option<String>,

    /// Whether to include timestamps
    #[serde(default = "default::bool_true")]
    pub include_timestamp: bool,

    /// Environment (development, testing, production)
    #[serde(default = "default_environment")]
    pub environment: String,
}

mod default {
    pub fn bool_true() -> bool { true }
}

fn default_level() -> String { "info".to_string() }

fn default_format() -> String { "json".to_string() }

fn default_log_file() -> Option<String> { None }

fn default_environment() -> String { "development".to_string() }

impl LoggingConfig {
    /// Create configuration from environment variables.
    pub fn from_env(level: &str, format: &str, log_file: Option<&str>) -> Self {
        Self {
            level: std::env::var("RUST_LOG")
                .ok()
                .unwrap_or_else(|| level.to_string()),
            format: std::env::var("HORIZON_LOG_FORMAT")
                .ok()
                .unwrap_or_else(|| format.to_string()),
            log_file: std::env::var("HORIZON_LOG_FILE")
                .ok()
                .or(log_file.map(|s| s.to_string())),
            environment: std::env::var("HORIZON_ENV").unwrap_or_else(|_| "development".to_string()),
            ..Default::default()
        }
    }

    /// Build the tracing subscriber from this configuration.
    pub fn build(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let level: LevelFilter = self.level.parse().unwrap_or_else(|_| LevelFilter::INFO);

        match self.format.as_str() {
            "json" => self.build_json_subscriber(level),
            "pretty" => self.build_pretty_subscriber(level),
            "compact" => self.build_compact_subscriber(level),
            _ => self.build_json_subscriber(level),
        }
    }

    /// Build a JSON subscriber for production logging.
    fn build_json_subscriber(&self, level: LevelFilter) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let subscriber = fmt::layer()
            .json()
            .with_timer(fmt::time::UtcTime::rfc_3339());

        if let Some(ref log_file) = self.log_file {
            let file_appender = tracing_appender::rolling::hourly(
                PathBuf::from(log_file)
                    .parent()
                    .unwrap_or(&PathBuf::from(".")),
                PathBuf::from(log_file)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .as_ref(),
            );
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            let file_layer = fmt::layer().json().with_writer(non_blocking);
            Box::new(
                Registry::default()
                    .with(level)
                    .with(subscriber)
                    .with(file_layer),
            )
        }
        else {
            Box::new(Registry::default().with(level).with(subscriber))
        }
    }

    /// Build a pretty subscriber for development logging.
    fn build_pretty_subscriber(&self, level: LevelFilter) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let subscriber = fmt::layer()
            .pretty()
            .with_timer(fmt::time::UtcTime::rfc_3339());
        Box::new(Registry::default().with(level).with(subscriber))
    }

    /// Build a compact subscriber for testing.
    fn build_compact_subscriber(&self, level: LevelFilter) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let subscriber = fmt::layer()
            .compact()
            .with_timer(fmt::time::UtcTime::rfc_3339());
        Box::new(Registry::default().with(level).with(subscriber))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "json");
        assert_eq!(config.environment, "development");
    }

    #[test]
    fn test_config_from_env() {
        // Safe in test context - used to verify environment-based config
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
            std::env::set_var("HORIZON_LOG_FORMAT", "pretty");
        }

        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.level, "debug");
        assert_eq!(config.format, "pretty");

        // Safe in test context - cleanup after test
        unsafe {
            std::env::remove_var("RUST_LOG");
            std::env::remove_var("HORIZON_LOG_FORMAT");
        }
    }

    #[test]
    fn test_build_json_subscriber() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "json".to_string(),
            log_file: None,
            ..Default::default()
        };
        let _subscriber = config.build();
    }

    #[test]
    fn test_build_pretty_subscriber() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "pretty".to_string(),
            log_file: None,
            ..Default::default()
        };
        let _subscriber = config.build();
    }
}
