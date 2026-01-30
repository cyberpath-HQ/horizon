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
