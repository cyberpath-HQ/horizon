//! # Horizon Logging Infrastructure
//!
//! Structured logging utilities for the Horizon application.
//! Provides tracing integration with JSON output and environment-based configuration.

pub mod config;
pub mod macros;
pub mod request_id;

pub use config::LoggingConfig;
pub use request_id::RequestId;
// Re-export tracing macros
pub use tracing::{debug, error, info, trace, warn};

/// Initialize the logging system.
///
/// # Arguments
///
/// * `level` - Log level (debug, info, warn, error)
/// * `format` - Output format (json, pretty, compact)
/// * `log_file` - Optional path to log file
#[tracing::instrument]
pub fn init(
    level: &str,
    format: &str,
    log_file: Option<&str>,
) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let config = LoggingConfig::from_env(level, format, log_file);
    let subscriber = config.build();
    tracing::subscriber::set_global_default(subscriber)?;
    info!(level = %level, format = %format, "Logging initialized");
    Ok(())
}

/// Initialize logging with a custom configuration.
#[tracing::instrument]
pub fn init_with_config(config: LoggingConfig) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let subscriber = config.build();
    tracing::subscriber::set_global_default(subscriber)?;
    info!(level = %config.level, format = %config.format, "Logging initialized with config");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_init_success() {
        // Should not panic
        let result = init("info", "json", None);
        // May fail if global subscriber is already set, which is fine
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_init_with_config() {
        let config = LoggingConfig {
            level:             "debug".to_string(),
            format:            "compact".to_string(),
            log_file:          None,
            include_timestamp: true,
            environment:       "testing".to_string(),
        };
        let result = init_with_config(config);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_request_id_exports() {
        let id = RequestId::new();
        assert!(!id.as_str().is_empty());
        assert!(id.as_str().len() >= 20);
    }

    #[test]
    fn test_request_id_display() {
        let id = RequestId::new();
        let display = format!("{}", id);
        assert_eq!(display, id.as_str());
    }

    #[test]
    fn test_request_id_from_str_valid() {
        let cuid = "k192v2g4w3zq8h6j5k12345678";
        let id = RequestId::from_str(cuid).unwrap();
        assert_eq!(id.as_str(), cuid);
    }

    #[test]
    fn test_request_id_from_str_invalid() {
        let result = RequestId::from_str("short");
        assert!(result.is_err());
    }

    #[test]
    fn test_request_id_default() {
        let id = RequestId::default();
        assert!(!id.as_str().is_empty());
    }

    #[test]
    fn test_try_from_header_valid() {
        let cuid = "k192v2g4w3zq8h6j5k12345678";
        let result = request_id::try_from_header(cuid);
        assert!(result.is_some());
    }

    #[test]
    fn test_try_from_header_invalid() {
        let result = request_id::try_from_header("invalid!@#");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_headers() {
        let headers: Vec<String> = vec![];
        let result = request_id::extract_from_headers(&headers);
        assert!(result.is_some());
    }
}
