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

use error::Result;

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
                .expect("HORIZON_JWT_SECRET environment variable must be set"),
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
