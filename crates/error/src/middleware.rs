//! # Error Handling Middleware
//!
//! Axum middleware for handling errors and logging requests.
//!
//! ## Usage
//!
//! ```rust
//! use error::{
//!     middleware::{ErrorHandler, IntoResponse},
//!     AppError,
//! };
//! use axum::{body::Body, response::Response};
//!
//! let handler = ErrorHandler::new(false);
//! let error = AppError::not_found("User not found");
//! let response = handler.to_response(&error);
//! ```

use axum::{body::Body, http::StatusCode, response::Response};

use crate::{response::ApiResponse, AppError};

/// Error handler that converts errors to HTTP responses.
#[derive(Clone)]
pub struct ErrorHandler {
    /// Whether to include error details in response.
    pub include_details: bool,
}

impl ErrorHandler {
    /// Create a new error handler.
    #[inline]
    pub fn new(include_details: bool) -> Self {
        Self {
            include_details,
        }
    }

    /// Convert an error to a response.
    pub fn to_response(&self, err: &AppError) -> Response {
        let status = err.status();
        let code = err.code();
        let message = if self.include_details {
            err.message()
        }
        else {
            match status {
                StatusCode::INTERNAL_SERVER_ERROR => "Internal server error".to_string(),
                StatusCode::NOT_FOUND => "Resource not found".to_string(),
                StatusCode::BAD_REQUEST => "Bad request".to_string(),
                StatusCode::UNAUTHORIZED => "Unauthorized".to_string(),
                StatusCode::FORBIDDEN => "Forbidden".to_string(),
                StatusCode::TOO_MANY_REQUESTS => "Rate limit exceeded".to_string(),
                _ => "An error occurred".to_string(),
            }
        };

        let response = ApiResponse::<()>::error(code, message);

        let mut res = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&response).unwrap()))
            .unwrap();

        // Add retry-after header for rate limit errors
        if let AppError::RateLimit {
            retry_after,
            ..
        } = err
        {
            res.headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());
        }

        res
    }
}

/// Middleware for logging requests.
#[derive(Clone)]
pub struct RequestLogger {
    /// Skip logging for these paths.
    pub skip_paths: Vec<&'static str>,
}

impl RequestLogger {
    /// Create a new request logger.
    #[inline]
    pub fn new() -> Self {
        Self {
            skip_paths: vec!["/health", "/ready"],
        }
    }

    /// Check if a path should be skipped.
    pub fn should_skip(&self, path: &str) -> bool { self.skip_paths.iter().any(|p| path.starts_with(p)) }
}

/// Middleware for recovering from panics.
#[derive(Clone)]
pub struct PanicRecovery {
    /// Custom panic message.
    pub message: &'static str,
}

impl PanicRecovery {
    /// Create a new panic recovery middleware.
    #[inline]
    pub fn new(message: &'static str) -> Self {
        Self {
            message,
        }
    }
}

/// Trait for converting values to responses.
pub trait IntoResponse {
    /// Convert to a response.
    fn into_response(self) -> Response;
}

impl IntoResponse for ApiResponse<()> {
    fn into_response(self) -> Response {
        let status = match self {
            ApiResponse::Success {
                ..
            } => StatusCode::OK,
            ApiResponse::Error {
                ..
            } => StatusCode::BAD_REQUEST,
        };

        let body = serde_json::to_string(&self).unwrap_or_default();

        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

impl IntoResponse for Response {
    fn into_response(self) -> Response { self }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Body::from(self))
            .unwrap()
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Body::from(self))
            .unwrap()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let handler = ErrorHandler::new(false);
        handler.to_response(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_handler() {
        let handler = ErrorHandler::new(false);
        let err = AppError::not_found("User not found");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_handler_with_details() {
        let handler = ErrorHandler::new(true);
        let err = AppError::internal("Detailed error message");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_request_logger_skip() {
        let logger = RequestLogger::new();
        assert!(logger.should_skip("/health"));
        assert!(!logger.should_skip("/api/users"));
    }
}
