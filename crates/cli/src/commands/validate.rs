//! # CLI Validate Command
//!
//! Configuration validation for the Horizon CLI.

use error::{AppError, Result};

/// Validates the CLI configuration
///
/// # Returns
///
/// A `Result` indicating success or failure.
pub fn validate() -> Result<()> {
    // Check required environment variables
    let required_vars = [
        "HORIZON_DATABASE_HOST",
        "HORIZON_DATABASE_PORT",
        "HORIZON_DATABASE_NAME",
        "HORIZON_DATABASE_USER",
        "HORIZON_DATABASE_PASSWORD",
    ];

    let mut missing = Vec::new();
    for var in &required_vars {
        if std::env::var(var).is_err() {
            missing.push(var);
        }
    }

    if !missing.is_empty() {
        return Err(AppError::validation(format!(
            "Missing required environment variables: {:?}",
            missing
        )));
    }

    Ok(())
}
