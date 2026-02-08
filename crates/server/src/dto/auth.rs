//! # Authentication Data Transfer Objects
//!
//! Request and response types for authentication endpoints.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request body for user login
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct LoginRequest {
    /// User's email address
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// User's password
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Request body for initial admin setup
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct SetupRequest {
    /// Admin email address
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// Admin password
    #[validate(length(
        min = 12,
        max = 256,
        message = "Password must be between 12 and 256 characters"
    ))]
    pub password: String,

    /// Display name for the admin user
    #[validate(length(
        min = 1,
        max = 255,
        message = "Display name must be between 1 and 255 characters"
    ))]
    pub display_name: String,
}

/// Request body for token refresh
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct RefreshRequest {
    /// The refresh token to use for obtaining new access token
    #[validate(length(min = 1, message = "Refresh token is required"))]
    pub refresh_token: String,
}

/// Response containing authentication tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthTokens {
    /// JWT access token for API requests
    pub access_token: String,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Token expiration time in seconds
    pub expires_in: u64,

    /// Token type (always "Bearer")
    #[serde(rename = "tokenType")]
    pub token_type: String,
}

/// Response containing user information after authentication
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedUser {
    /// Unique user identifier
    pub id: String,

    /// User's email address
    pub email: String,

    /// User's display name
    #[serde(rename = "displayName")]
    pub display_name: String,

    /// User's roles
    pub roles: Vec<String>,
}

/// Success response for authentication operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthSuccessResponse {
    /// Indicates operation success
    pub success: bool,

    /// Authenticated user information
    pub user: AuthenticatedUser,

    /// Authentication tokens
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tokens: Option<AuthTokens>,
}

/// Generic success response
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuccessResponse {
    /// Indicates operation success
    pub success: bool,

    /// Human-readable message
    pub message: String,
}

/// Error response for authentication operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthErrorResponse {
    /// Indicates operation failure
    pub success: bool,

    /// Error code
    pub code: String,

    /// Human-readable error message
    pub message: String,
}

impl AuthErrorResponse {
    /// Creates a new error response
    #[must_use]
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            success: false,
            code:    code.to_string(),
            message: message.to_string(),
        }
    }

    /// Unauthorized error
    pub fn unauthorized(message: &str) -> Self { Self::new("UNAUTHORIZED", message) }

    /// Bad request error
    pub fn bad_request(message: &str) -> Self { Self::new("BAD_REQUEST", message) }

    /// Conflict error (e.g., already configured)
    pub fn conflict(message: &str) -> Self { Self::new("CONFLICT", message) }

    /// Validation error
    pub fn validation(message: &str) -> Self { Self::new("VALIDATION_ERROR", message) }
}
