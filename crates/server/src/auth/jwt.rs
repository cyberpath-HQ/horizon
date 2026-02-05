//! # JWT Token Management
//!
//! JWT token generation and validation for API authentication.

use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

use jsonwebtoken::{EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use error::AppError;
use cuid2::CuidConstructor;

use crate::{JwtConfig, Result};

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// User email
    pub email: String,

    /// User roles
    pub roles: Vec<String>,

    /// Token issuer
    pub iss: String,

    /// Token audience
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: u64,

    /// Issued at (Unix timestamp)
    pub iat: u64,

    /// Unique token ID
    pub jti: String,
}

/// Creates a new JWT access token
///
/// # Arguments
///
/// * `config` - JWT configuration
/// * `user_id` - The user's unique identifier
/// * `email` - The user's email address
/// * `roles` - The user's roles
///
/// # Errors
///
/// Returns an error if token encoding fails.
pub fn create_access_token(config: &JwtConfig, user_id: &str, email: &str, roles: &[String]) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| AppError::unauthorized(format!("Failed to get current time: {}", e)))?;

    let issued_at = now.as_secs();
    let expiration = now + Duration::from_secs(config.expiration_seconds);
    let exp_timestamp = expiration.as_secs();

    let claims = Claims {
        sub:   user_id.to_string(),
        email: email.to_string(),
        roles: roles.to_vec(),
        iss:   config.issuer.clone(),
        aud:   config.audience.clone(),
        exp:   exp_timestamp,
        iat:   issued_at,
        jti:   CuidConstructor::new().with_length(32).create_id(),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_base64_secret(&config.secret)
            .map_err(|e| AppError::unauthorized(format!("Invalid JWT secret: {}", e)))?,
    )
    .map_err(|e| AppError::unauthorized(format!("Failed to encode token: {}", e)))?;

    Ok(token)
}

/// Validates a JWT token and returns the claims
///
/// # Arguments
///
/// * `config` - JWT configuration
/// * `token` - The JWT token to validate
///
/// # Errors
///
/// Returns an error if token validation fails.
pub fn validate_token(config: &JwtConfig, token: &str) -> Result<Claims> {
    let decoding_key = jsonwebtoken::DecodingKey::from_base64_secret(&config.secret)
        .map_err(|e| AppError::unauthorized(format!("Invalid JWT secret: {}", e)))?;

    let mut validation = Validation::default();
    let mut iss_set = HashSet::new();
    iss_set.insert(config.issuer.clone());
    validation.iss = Some(iss_set);
    let mut aud = HashSet::new();
    aud.insert(config.audience.clone());
    validation.aud = Some(aud);
    validation.validate_exp = true;

    let claims = jsonwebtoken::decode(token, &decoding_key, &validation)
        .map_err(|e| AppError::unauthorized(format!("Token validation failed: {}", e)))?;

    Ok(claims.claims)
}

/// Extracts the Bearer token from the Authorization header
///
/// # Arguments
///
/// * `auth_header` - The Authorization header value
///
/// # Returns
///
/// The token string if present, or None if missing/invalid.
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    if !auth_header.starts_with("Bearer ") {
        return None;
    }

    let token = auth_header.trim_start_matches("Bearer ").trim();

    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::JwtConfig;

    #[test]
    fn test_create_and_validate_token() {
        let secret = "test-secret-key-that-is-at-least-32-bytes-long";
        let config = JwtConfig {
            secret:             base64::engine::general_purpose::STANDARD.encode(secret),
            expiration_seconds: 3600,
            issuer:             "test-issuer".to_string(),
            audience:           "test-audience".to_string(),
        };

        let token = create_access_token(
            &config,
            "user-123",
            "test@example.com",
            &["admin".to_string()],
        )
        .expect("Failed to create token");

        assert!(!token.is_empty());

        let claims = validate_token(&config, &token).expect("Failed to validate token");

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.roles, vec!["admin"]);
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.aud, "test-audience");
    }

    #[test]
    fn test_extract_bearer_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-token";
        let auth_header = format!("Bearer {}", token);

        let extracted = extract_bearer_token(&auth_header).expect("Failed to extract token");

        assert_eq!(extracted, token);
    }

    #[test]
    fn test_extract_bearer_token_invalid_format() {
        assert!(extract_bearer_token("Basic abc123").is_none());
        assert!(extract_bearer_token("Bearer").is_none());
        assert!(extract_bearer_token("").is_none());
    }
}
