//! # Logging Configuration
//!
//! Configuration for the logging subsystem.
//! Supports environment variables and programmatic configuration.

use std::path::PathBuf;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

/// Allowed crates in the Horizon project - only logs from these crates will be shown
const ALLOWED_CRATES: &[&str] = &[
    "horizon",
    "server",
    "error",
    "logging",
    "auth",
    "entity",
    "migration",
    "sea_orm_migration",
    "app",
    "serve",
];

/// Logging configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Derivative)]
#[derivative(Default)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    #[derivative(Default(value = "\"info\".to_string()"))]
    pub level: String,

    /// Output format (json, compact)
    #[derivative(Default(value = "\"compact\".to_string()"))]
    pub format: String,

    /// Optional log file path
    #[derivative(Default(value = "None"))]
    pub log_file: Option<String>,

    /// Whether to include timestamps
    #[derivative(Default(value = "true"))]
    pub include_timestamp: bool,

    /// Environment (development, testing, production)
    #[derivative(Default(value = "\"development\".to_string()"))]
    pub environment: String,
}

impl LoggingConfig {
    /// Create configuration from environment variables.
    pub fn from_env(level: &str, format: &str, log_file: Option<&str>) -> Self {
        Self {
            level: level.to_string(),
            format: format.to_string(),
            log_file: std::env::var("HORIZON_LOG_FILE")
                .ok()
                .or(log_file.map(|s| s.to_string())),
            environment: std::env::var("HORIZON_ENV").unwrap_or_else(|_| "development".to_string()),
            ..Default::default()
        }
    }

    /// Build the tracing subscriber from this configuration.
    pub fn build(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let env_filter = self.build_env_filter();

        match self.format.as_str() {
            "json" => self.build_json_subscriber(env_filter),
            "compact" => self.build_compact_subscriber(env_filter),
            _ => self.build_compact_subscriber(env_filter),
        }
    }

    /// Build an EnvFilter that only allows logs from Horizon project crates.
    /// This filters both tracing and log crate messages (including SQLx).
    fn build_env_filter(&self) -> EnvFilter {
        // Use the level from CLI argument/config, not RUST_LOG env var
        let level = self.level.parse().unwrap_or(tracing::Level::INFO);
        let level_str = match level {
            tracing::Level::TRACE => "trace",
            tracing::Level::DEBUG => "debug",
            tracing::Level::INFO => "info",
            tracing::Level::WARN => "warn",
            tracing::Level::ERROR => "error",
        };

        // Only show logs from Horizon crates at the specified level
        // Silence all external dependencies (sqlx, tower, hyper, etc.)
        let allowed: Vec<String> = ALLOWED_CRATES
            .iter()
            .map(|c| format!("{}={}", c, level_str))
            .collect();

        let filter_str = format!("{},off", allowed.join(","));

        tracing::info!("Using log filter: {}", filter_str);
        EnvFilter::new(filter_str)
    }

    /// Build a JSON subscriber for production logging.
    fn build_json_subscriber(&self, filter: EnvFilter) -> Box<dyn tracing::Subscriber + Send + Sync> {
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
                    .with(filter)
                    .with(subscriber)
                    .with(file_layer),
            )
        }
        else {
            Box::new(Registry::default().with(filter).with(subscriber))
        }
    }

    /// Build a compact subscriber for testing.
    fn build_compact_subscriber(&self, filter: EnvFilter) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let subscriber = fmt::layer()
            .compact()
            .with_timer(fmt::time::UtcTime::rfc_3339());
        Box::new(Registry::default().with(filter).with(subscriber))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_config_default() {
        // Ensure HORIZON_ENV is not set for this test
        let orig = std::env::var("HORIZON_ENV").ok();
        unsafe {
            std::env::remove_var("HORIZON_ENV");
            std::env::remove_var("RUST_LOG");
            std::env::remove_var("HORIZON_LOG_FORMAT");
            std::env::remove_var("HORIZON_LOG_FILE");
        }

        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "json");
        assert_eq!(config.environment, "development");

        // Restore
        unsafe {
            if let Some(v) = orig {
                std::env::set_var("HORIZON_ENV", v);
            }
        }
    }

    #[test]
    fn test_config_from_env() {
        // Save original values
        let orig_rust_log = std::env::var("RUST_LOG").ok();
        let orig_format = std::env::var("HORIZON_LOG_FORMAT").ok();

        // Set test values
        unsafe {
            std::env::set_var("RUST_LOG", "debug");
            std::env::set_var("HORIZON_LOG_FORMAT", "compact");
        }

        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.level, "debug");
        assert_eq!(config.format, "compact");

        // Restore original values
        unsafe {
            match orig_rust_log {
                Some(v) => std::env::set_var("RUST_LOG", v),
                None => std::env::remove_var("RUST_LOG"),
            }
            match orig_format {
                Some(v) => std::env::set_var("HORIZON_LOG_FORMAT", v),
                None => std::env::remove_var("HORIZON_LOG_FORMAT"),
            }
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
    fn test_build_compact_subscriber() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "compact".to_string(),
            log_file: None,
            ..Default::default()
        };
        let _subscriber = config.build();
    }

    #[test]
    fn test_build_invalid_format_defaults_to_json() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "invalid_format".to_string(),
            log_file: None,
            ..Default::default()
        };
        let _subscriber = config.build();
    }

    #[test]
    fn test_build_invalid_level_defaults_to_info() {
        let config = LoggingConfig {
            level: "invalid_level".to_string(),
            format: "json".to_string(),
            log_file: None,
            ..Default::default()
        };
        let _subscriber = config.build();
    }

    #[test]
    fn test_config_with_log_file() {
        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_app.log");
        let config = LoggingConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            log_file: Some(log_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        let _subscriber = config.build();
        // Cleanup
        let _ = std::fs::remove_file(log_path);
    }

    #[test]
    fn test_config_environment_variable() {
        // Save original value
        let orig = std::env::var("HORIZON_ENV").ok();

        unsafe {
            std::env::set_var("HORIZON_ENV", "production");
        }

        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.environment, "production");

        // Restore
        unsafe {
            match orig {
                Some(v) => std::env::set_var("HORIZON_ENV", v),
                None => std::env::remove_var("HORIZON_ENV"),
            }
        }
    }

    #[test]
    fn test_config_log_file_variable() {
        // Save original value
        let orig = std::env::var("HORIZON_LOG_FILE").ok();

        unsafe {
            std::env::set_var("HORIZON_LOG_FILE", "/custom/path.log");
        }

        let config = LoggingConfig::from_env("info", "json", None);
        assert_eq!(config.log_file, Some("/custom/path.log".to_string()));

        // Restore
        unsafe {
            match orig {
                Some(v) => std::env::set_var("HORIZON_LOG_FILE", v),
                None => std::env::remove_var("HORIZON_LOG_FILE"),
            }
        }
    }
}
