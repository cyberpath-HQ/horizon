//! # API Key Data Transfer Objects
//!
//! Request and response types for API key management endpoints.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Maximum allowed expiration time in seconds (100 years)
/// This prevents integer overflow and excessive memory allocation
const MAX_EXPIRATION_SECONDS: u64 = 100 * 365 * 24 * 60 * 60; // 100 years

/// Request to create a new API key
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the API key
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name:               String,
    /// JSON permissions object defining what this key can access
    pub permissions:        Option<serde_json::Value>,
    /// Optional expiration time in seconds from now (if not set, key does not expire)
    /// Maximum: 100 years in seconds
    #[validate(range(min = 1, max = MAX_EXPIRATION_SECONDS, message = "Expiration time must be between 1 second and 100 years"))]
    pub expires_in_seconds: Option<u64>,
}

/// Response after creating an API key (includes the full key, shown only once)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateApiKeyResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// The created API key details
    pub api_key: ApiKeyDetail,
    /// The full API key value (only shown on creation, never again)
    pub key:     String,
}

/// API key detail response (without the actual key)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyDetail {
    /// Unique identifier for the API key
    pub id:           String,
    /// Human-readable name
    pub name:         String,
    /// Key prefix (first 8 chars) for identification
    pub key_prefix:   String,
    /// Permissions JSON
    pub permissions:  serde_json::Value,
    /// When the key expires (if ever)
    pub expires_at:   Option<String>,
    /// When the key was last used
    pub last_used_at: Option<String>,
    /// IP address of last use
    pub last_used_ip: Option<String>,
    /// Creation timestamp
    pub created_at:   String,
    /// User ID that owns this key
    pub user_id:      String,
}

/// Response for API key list
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyListResponse {
    /// Whether the operation was successful
    pub success:    bool,
    /// List of API keys
    pub api_keys:   Vec<ApiKeyDetail>,
    /// Pagination info
    pub pagination: super::users::PaginationInfo,
}

/// Request to update API key permissions
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct UpdateApiKeyPermissionsRequest {
    /// New permissions JSON
    pub permissions: serde_json::Value,
}

/// Response for API key rotation
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotateApiKeyResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// The rotated API key details
    pub api_key: ApiKeyDetail,
    /// The new full API key value (only shown once)
    pub key:     String,
}

/// API key usage statistics
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyUsageStats {
    /// Total number of API calls made with this key
    pub total_requests:    u64,
    /// Requests in the last 24 hours
    pub requests_last_24h: u64,
    /// Requests in the last 7 days
    pub requests_last_7d:  u64,
    /// Most recent usage entries
    pub recent_usage:      Vec<ApiKeyUsageEntry>,
}

/// A single API key usage log entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyUsageEntry {
    /// Endpoint that was accessed
    pub endpoint:    String,
    /// HTTP method
    pub method:      String,
    /// HTTP status code
    pub status_code: i16,
    /// IP address
    pub ip_address:  Option<String>,
    /// Timestamp
    pub created_at:  String,
}

/// Response for API key usage statistics
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyUsageResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Usage statistics
    pub usage:   ApiKeyUsageStats,
}

/// Query parameters for API key list
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyListQuery {
    /// Page number (1-based, default: 1)
    pub page:     Option<u64>,
    /// Items per page (default: 20, max: 100)
    pub per_page: Option<u64>,
    /// Search by name or prefix
    pub search:   Option<String>,
}

impl ApiKeyListQuery {
    /// Get page number (1-based, default: 1)
    pub fn page(&self) -> u64 { self.page.unwrap_or(1).max(1) }

    /// Get items per page (default: 20, max: 100)
    pub fn per_page(&self) -> u64 { self.per_page.unwrap_or(20).clamp(1, 100) }
}
