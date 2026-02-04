//! # Horizon API Server
//!
//! Axum-based HTTP API server for Horizon CMDB.
//!
//! ## Modules
//!
//! - [`auth`]: Authentication endpoints and JWT handling
//! - [`dto`]: Request/response data transfer objects
//! - [`middleware`]: HTTP middleware (CORS, auth, logging)
//! - [`router`]: API route configuration

pub mod auth;
pub mod dto;
pub mod middleware;
pub mod refresh_tokens;
pub mod router;
pub mod token_blacklist;

pub use router::create_app_router;

/// Application state shared across request handlers
#[derive(Clone, Debug)]
pub struct AppState {
    /// Database connection pool
    pub db:         sea_orm::DbConn,
    /// JWT configuration
    pub jwt_config: JwtConfig,
    /// Redis connection for token blacklisting
    pub redis:      redis::Client,
}

/// JWT configuration for token generation and validation
#[derive(Clone, Debug)]
pub struct JwtConfig {
    /// Secret key for signing tokens (base64 encoded)
    pub secret:             String,
    /// Token expiration time in seconds
    pub expiration_seconds: u64,
    /// Token issuer
    pub issuer:             String,
    /// Audience claim
    pub audience:           String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret:             std::env::var("HORIZON_JWT_SECRET")
                .unwrap_or_else(|_| "default-dev-secret-change-in-production".to_string()),
            expiration_seconds: 3600, // 1 hour
            issuer:             "horizon".to_string(),
            audience:           "horizon-api".to_string(),
        }
    }
}

/// Server initialization result
#[derive(Debug)]
pub struct ServerResult {
    /// The address the server is bound to
    pub address:    String,
    /// Server start timestamp for logging
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl ServerResult {
    /// Creates a new server result
    #[must_use]
    pub fn new(address: &str) -> Self {
        Self {
            address:    address.to_string(),
            started_at: chrono::Utc::now(),
        }
    }
}

/// Application result type
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error type for server operations
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Configuration error: {message}")]
    Config {
        message: String,
    },

    #[error("Database error: {message}")]
    Database {
        message: String,
    },

    #[error("Authentication error: {message}")]
    Auth {
        message: String,
    },

    #[error("Token error: {message}")]
    Token {
        message: String,
    },
}

impl AppError {
    /// Create a configuration error
    #[inline]
    pub fn config(message: impl ToString) -> Self {
        Self::Config {
            message: message.to_string(),
        }
    }

    /// Create a database error
    #[inline]
    pub fn database(message: impl ToString) -> Self {
        Self::Database {
            message: message.to_string(),
        }
    }

    /// Create an authentication error
    #[inline]
    pub fn auth(message: impl ToString) -> Self {
        Self::Auth {
            message: message.to_string(),
        }
    }

    /// Create a token error
    #[inline]
    pub fn token(message: impl ToString) -> Self {
        Self::Token {
            message: message.to_string(),
        }
    }
}

/// Convert Sea-ORM errors to AppError
impl From<sea_orm::DbErr> for AppError {
    fn from(err: sea_orm::DbErr) -> Self { Self::database(err.to_string()) }
}

/// Convert anyhow errors to AppError
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::Config {
            message: err.to_string(),
        }
    }
}

/// Convert Redis errors to AppError
impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        Self::Config {
            message: format!("Redis error: {}", err),
        }
    }
}

/// Convert AppError to HTTP response
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AppError::Config {
                ..
            } => http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Database {
                ..
            } => http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Auth {
                ..
            } => http::StatusCode::UNAUTHORIZED,
            AppError::Token {
                ..
            } => http::StatusCode::UNAUTHORIZED,
        };

        let body = serde_json::json!({
            "success": false,
            "code": match self {
                AppError::Config { .. } => "CONFIG_ERROR",
                AppError::Database { .. } => "DATABASE_ERROR",
                AppError::Auth { .. } => "AUTHENTICATION_ERROR",
                AppError::Token { .. } => "TOKEN_ERROR",
            },
            "message": self.to_string()
        });

        (status, axum::Json(body)).into_response()
    }
}
