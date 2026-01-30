//! # Error Traits
//!
//! Conversion traits for error handling.

use std::fmt;

use crate::{AppError, Result};

/// Trait for adding context to errors.
pub trait Context<T> {
    fn with_context<C: ToString>(self, context: C) -> Result<T>;
    fn context<C: ToString>(self, context: C) -> Result<T>
    where
        Self: Sized;
}

/// Extension methods for Result types.
pub trait ResultExt<T> {
    fn with_context<C: ToString>(self, context: C) -> Result<T>;
    fn context<C: ToString>(self, context: C) -> Result<T>
    where
        Self: Sized;
    fn log_error(self) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: Into<AppError> + std::fmt::Display,
{
    fn with_context<C: ToString>(self, context: C) -> Result<T> {
        self.map_err(|e| {
            let err: AppError = e.into();
            err.context(context)
        })
    }

    fn context<C: ToString>(self, context: C) -> Result<T>
    where
        Self: Sized,
    {
        self.with_context(context)
    }

    fn log_error(self) -> Result<T> {
        self.map_err(|e| {
            let err: AppError = e.into();
            tracing::error!(error = %err, "Error occurred");
            err
        })
    }
}

/// Wrap an error with additional context.
#[track_caller]
pub fn wrap_err<E, C>(err: E, context: C) -> AppError
where
    E: Into<AppError>,
    C: fmt::Display,
{
    let app_err: AppError = err.into();
    app_err.context(context)
}

/// Log an error at the specified level.
pub fn log_err<E>(err: E, level: &str) -> AppError
where
    E: Into<AppError> + std::fmt::Display,
{
    let app_err: AppError = err.into();
    match level {
        "debug" => tracing::debug!(error = %app_err, "Error logged at debug level"),
        "info" => tracing::info!(error = %app_err, "Error logged at info level"),
        "warn" => tracing::warn!(error = %app_err, "Error logged at warn level"),
        "error" => tracing::error!(error = %app_err, "Error logged at error level"),
        _ => tracing::trace!(error = %app_err, "Error logged"),
    }
    app_err
}

/// Convert a Result to an Option, logging errors.
pub fn ok_or_log<T>(result: Result<T>) -> Option<T> {
    result
        .map_err(|e| {
            tracing::error!(error = %e, "Operation failed");
            e
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context() {
        let result: Result<i32> = Err(AppError::not_found("User"));
        let result = result.context("Failed to get user");

        assert!(result.is_err());
    }

    #[test]
    fn test_log_error() {
        let result: Result<i32> = Err(AppError::not_found("User"));
        let result = result.log_error();

        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_err() {
        let err = wrap_err(
            AppError::not_found("User not found"),
            "Failed to process user",
        );
        // The context method returns a new error
        assert_eq!(
            format!("{}", err),
            "NotFound: Failed to process user: User not found"
        );
    }

    #[test]
    fn test_ok_or_log() {
        let result: Result<i32> = Ok(42);
        assert_eq!(ok_or_log(result), Some(42));

        let result: Result<i32> = Err(AppError::not_found("User"));
        assert_eq!(ok_or_log(result), None);
    }
}
