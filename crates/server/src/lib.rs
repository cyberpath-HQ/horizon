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
pub mod utils;

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
    /// Server start time for uptime calculation
    pub start_time: std::time::Instant,
}

use ::auth::JwtConfig;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_result_new() {
        let address = "127.0.0.1:8080";
        let result = ServerResult::new(address);
        assert_eq!(result.address, address);
        assert!(result.started_at.timestamp() > 0); // Should have a valid timestamp
    }
}
