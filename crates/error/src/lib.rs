//! # Horizon Error Infrastructure
//!
//! Error types and API response handling for the Horizon application.

pub mod codes;
pub mod middleware;
pub mod response;
pub mod traits;

pub use response::{ApiResponse, ApiResponseBuilder, PaginationMeta};
pub use traits::{Context, ResultExt};
pub use middleware::{ErrorHandler, IntoResponse, PanicRecovery, RequestLogger};

/// Convenience type alias for Result with AppError.
pub type Result<T, E = AppError> = std::result::Result<T, E>;

/// Main application error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("NotFound: {message}")]
    NotFound {
        message: String,
    },

    #[error("BadRequest: {message}")]
    BadRequest {
        message: String,
    },

    #[error("Unauthorized: {message}")]
    Unauthorized {
        message: String,
    },

    #[error("Forbidden: {message}")]
    Forbidden {
        message: String,
    },

    #[error("Conflict: {message}")]
    Conflict {
        message: String,
    },

    #[error("Validation: {message}")]
    Validation {
        message: String,
    },

    #[error("RateLimit: {message}")]
    RateLimit {
        message:     String,
        retry_after: u64,
    },

    #[error("Internal: {message}")]
    Internal {
        message: String,
    },

    #[error("Database: {message}")]
    Database {
        message: String,
    },

    #[error("IO: {message}")]
    Io {
        message: String,
    },
}

impl AppError {
    /// Create a not found error.
    #[inline]
    pub fn not_found(resource: impl ToString) -> Self {
        Self::NotFound {
            message: resource.to_string(),
        }
    }

    /// Create a bad request error.
    #[inline]
    pub fn bad_request(message: impl ToString) -> Self {
        Self::BadRequest {
            message: message.to_string(),
        }
    }

    /// Create an unauthorized error.
    #[inline]
    pub fn unauthorized(message: impl ToString) -> Self {
        Self::Unauthorized {
            message: message.to_string(),
        }
    }

    /// Create a forbidden error.
    #[inline]
    pub fn forbidden(message: impl ToString) -> Self {
        Self::Forbidden {
            message: message.to_string(),
        }
    }

    /// Create a conflict error.
    #[inline]
    pub fn conflict(message: impl ToString) -> Self {
        Self::Conflict {
            message: message.to_string(),
        }
    }

    /// Create a validation error.
    #[inline]
    pub fn validation(message: impl ToString) -> Self {
        Self::Validation {
            message: message.to_string(),
        }
    }

    /// Create an internal error.
    #[inline]
    pub fn internal(message: impl ToString) -> Self {
        Self::Internal {
            message: message.to_string(),
        }
    }

    /// Create a database error.
    #[inline]
    pub fn database(message: impl ToString) -> Self {
        Self::Database {
            message: message.to_string(),
        }
    }

    /// Create a rate limit error.
    #[inline]
    pub fn rate_limited(retry_after: u64) -> Self {
        Self::RateLimit {
            message: "Rate limit exceeded".to_string(),
            retry_after,
        }
    }

    /// Get the HTTP status code.
    pub fn status(&self) -> http::StatusCode {
        match self {
            AppError::NotFound {
                ..
            } => http::StatusCode::NOT_FOUND,
            AppError::BadRequest {
                ..
            } => http::StatusCode::BAD_REQUEST,
            AppError::Unauthorized {
                ..
            } => http::StatusCode::UNAUTHORIZED,
            AppError::Forbidden {
                ..
            } => http::StatusCode::FORBIDDEN,
            AppError::Conflict {
                ..
            } => http::StatusCode::CONFLICT,
            AppError::Validation {
                ..
            } => http::StatusCode::UNPROCESSABLE_ENTITY,
            AppError::RateLimit {
                ..
            } => http::StatusCode::TOO_MANY_REQUESTS,
            AppError::Internal {
                ..
            } => http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Database {
                ..
            } => http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io {
                ..
            } => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::NotFound {
                ..
            } => "NOT_FOUND",
            AppError::BadRequest {
                ..
            } => "BAD_REQUEST",
            AppError::Unauthorized {
                ..
            } => "UNAUTHORIZED",
            AppError::Forbidden {
                ..
            } => "FORBIDDEN",
            AppError::Conflict {
                ..
            } => "CONFLICT",
            AppError::Validation {
                ..
            } => "VALIDATION_ERROR",
            AppError::RateLimit {
                ..
            } => "RATE_LIMIT_EXCEEDED",
            AppError::Internal {
                ..
            } => "INTERNAL_ERROR",
            AppError::Database {
                ..
            } => "DATABASE_ERROR",
            AppError::Io {
                ..
            } => "IO_ERROR",
        }
    }

    /// Get the error message.
    pub fn message(&self) -> String {
        match self {
            AppError::NotFound {
                message,
                ..
            } => message.clone(),
            AppError::BadRequest {
                message,
                ..
            } => message.clone(),
            AppError::Unauthorized {
                message,
                ..
            } => message.clone(),
            AppError::Forbidden {
                message,
                ..
            } => message.clone(),
            AppError::Conflict {
                message,
                ..
            } => message.clone(),
            AppError::Validation {
                message,
                ..
            } => message.clone(),
            AppError::RateLimit {
                message,
                ..
            } => message.clone(),
            AppError::Internal {
                message,
                ..
            } => message.clone(),
            AppError::Database {
                message,
                ..
            } => message.clone(),
            AppError::Io {
                message,
                ..
            } => message.clone(),
        }
    }

    /// Add context to the error.
    #[inline]
    pub fn context(self, context: impl ToString) -> Self {
        let context_msg = context.to_string();
        match self {
            AppError::NotFound {
                message,
            } => {
                Self::NotFound {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::BadRequest {
                message,
            } => {
                Self::BadRequest {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Unauthorized {
                message,
            } => {
                Self::Unauthorized {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Forbidden {
                message,
            } => {
                Self::Forbidden {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Conflict {
                message,
            } => {
                Self::Conflict {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Validation {
                message,
            } => {
                Self::Validation {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::RateLimit {
                message,
                retry_after,
            } => {
                Self::RateLimit {
                    message: format!("{}: {}", context_msg, message),
                    retry_after,
                }
            },
            AppError::Internal {
                message,
            } => {
                Self::Internal {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Database {
                message,
            } => {
                Self::Database {
                    message: format!("{}: {}", context_msg, message),
                }
            },
            AppError::Io {
                message,
            } => {
                Self::Io {
                    message: format!("{}: {}", context_msg, message),
                }
            },
        }
    }
}

/// Convert anyhow errors to AppError.
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal {
            message: err.to_string(),
        }
    }
}

/// Convert std::io errors to AppError.
impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
        }
    }
}

/// Convert String to AppError.
impl From<String> for AppError {
    fn from(s: String) -> Self {
        Self::BadRequest {
            message: s,
        }
    }
}

/// Convert &str to AppError.
impl From<&str> for AppError {
    fn from(s: &str) -> Self { Self::from(s.to_string()) }
}
