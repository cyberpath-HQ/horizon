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

        let body_str = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"success":false,"code":"INTERNAL_ERROR","message":"Internal server error"}"#.to_string()
        });

        let mut res = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(body_str))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal server error"))
                    .unwrap()
            });

        // Add retry-after header for rate limit errors
        if let AppError::RateLimit {
            retry_after,
            ..
        } = err &&
            let Ok(retry_val) = retry_after.to_string().parse::<axum::http::HeaderValue>()
        {
            let _ = res.headers_mut().insert("Retry-After", retry_val);
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

impl Default for RequestLogger {
    fn default() -> Self { Self::new() }
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

// Implement axum's IntoResponse trait for AppError
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
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
        assert!(logger.should_skip("/ready"));
        assert!(!logger.should_skip("/api/users"));
        assert!(!logger.should_skip("/v1/assets"));
    }

    #[test]
    fn test_error_handler_rate_limit() {
        let handler = ErrorHandler::new(false);
        let err = AppError::rate_limited(60);
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("Retry-After"));
    }

    #[test]
    fn test_error_handler_different_status_codes() {
        let handler = ErrorHandler::new(false);

        // Test all error types
        assert_eq!(
            handler.to_response(&AppError::not_found("x")).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            handler.to_response(&AppError::bad_request("x")).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            handler.to_response(&AppError::unauthorized("x")).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            handler.to_response(&AppError::forbidden("x")).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            handler.to_response(&AppError::conflict("x")).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            handler.to_response(&AppError::validation("x")).status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            handler.to_response(&AppError::internal("x")).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            handler.to_response(&AppError::database("x")).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            handler.to_response(&AppError::rate_limited(1)).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            handler
                .to_response(&AppError::Io {
                    message: "x".to_string(),
                })
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_handler_response_has_content_type() {
        let handler = ErrorHandler::new(false);
        let err = AppError::not_found("Test");
        let response = handler.to_response(&err);

        assert!(response.headers().contains_key("Content-Type"));
    }

    #[test]
    fn test_error_handler_response_is_json() {
        let handler = ErrorHandler::new(true);
        let err = AppError::bad_request("Invalid input");
        let response = handler.to_response(&err);

        let content_type = response.headers().get("Content-Type").unwrap();
        assert!(content_type.to_str().unwrap().contains("application/json"));
    }

    #[test]
    fn test_error_handler_retry_after_header() {
        let handler = ErrorHandler::new(false);
        let err = AppError::rate_limited(120);
        let response = handler.to_response(&err);

        let retry_after = response.headers().get("Retry-After").unwrap();
        assert_eq!(retry_after.to_str().unwrap(), "120");
    }

    #[test]
    fn test_panic_recovery_new() {
        let panic_handler = PanicRecovery::new("Custom panic message");
        assert_eq!(panic_handler.message, "Custom panic message");
    }

    #[test]
    fn test_request_logger_default_skip_paths() {
        let logger = RequestLogger::new();
        assert_eq!(logger.skip_paths.len(), 2);
        assert!(logger.skip_paths.contains(&"/health"));
        assert!(logger.skip_paths.contains(&"/ready"));
    }

    #[test]
    fn test_into_response_for_api_response_success() {
        let response: ApiResponse<()> = ApiResponse::ok(());
        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::OK);
    }

    #[test]
    fn test_into_response_for_api_response_error() {
        let response: ApiResponse<()> = ApiResponse::error("CODE", "message");
        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_into_response_for_response() {
        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())
            .unwrap();
        let result = response.into_response();
        assert_eq!(result.status(), StatusCode::ACCEPTED);
    }

    #[test]
    fn test_into_response_for_static_str() {
        let response: &'static str = "Hello, World!";
        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::OK);
        assert!(http_response.headers().contains_key("Content-Type"));
    }

    #[test]
    fn test_into_response_for_string() {
        let response = String::from("Hello, World!");
        let http_response = response.into_response();
        assert_eq!(http_response.status(), StatusCode::OK);
        assert!(http_response.headers().contains_key("Content-Type"));
    }

    #[test]
    fn test_into_response_for_app_error() {
        let app_error = AppError::not_found("Resource not found");
        let http_response = app_error.into_response();
        assert_eq!(http_response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_handler_with_different_error_details() {
        let handler = ErrorHandler::new(true);
        let err = AppError::validation("Field is required");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(response.headers().contains_key("Content-Type"));
    }

    #[test]
    fn test_error_handler_authorization_error() {
        let handler = ErrorHandler::new(false);
        let err = AppError::unauthorized("Invalid token");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_error_handler_forbidden_error() {
        let handler = ErrorHandler::new(false);
        let err = AppError::forbidden("Access denied");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_error_handler_conflict_error() {
        let handler = ErrorHandler::new(false);
        let err = AppError::conflict("Resource already exists");
        let response = handler.to_response(&err);

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
