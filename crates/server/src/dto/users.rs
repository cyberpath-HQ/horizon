//! # User Data Transfer Objects
//!
//! Request and response types for user management endpoints.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Response for user profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserProfileResponse {
    /// User's unique identifier
    pub id:                String,
    /// User's email address
    pub email:             String,
    /// User's username
    pub username:          String,
    /// User's first name
    pub first_name:        Option<String>,
    /// User's last name
    pub last_name:         Option<String>,
    /// User's avatar URL
    pub avatar_url:        Option<String>,
    /// User's account status
    pub status:            String,
    /// Whether MFA is enabled
    pub mfa_enabled:       bool,
    /// User's roles
    pub roles:             Vec<String>,
    /// When email was verified
    pub email_verified_at: Option<String>,
    /// Last login timestamp
    pub last_login_at:     Option<String>,
    /// Account creation timestamp
    pub created_at:        String,
    /// Last update timestamp
    pub updated_at:        String,
}

/// Request to create a new user
#[derive(Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct CreateUserRequest {
    /// User's email address
    #[validate(email(message = "Invalid email format"))]
    pub email:    String,
    /// User's username
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: String,
    /// User's password
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    /// Role to assign to the user (admin, manager, viewer, user)
    pub role:     Option<String>,
}

/// Request to update user profile
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct UpdateUserProfileRequest {
    /// New first name
    #[validate(length(max = 255, message = "First name must not exceed 255 characters"))]
    pub first_name: Option<String>,
    /// New last name
    #[validate(length(max = 255, message = "Last name must not exceed 255 characters"))]
    pub last_name:  Option<String>,
    /// New avatar URL
    #[validate(url(message = "Invalid avatar URL"))]
    pub avatar_url: Option<String>,
}

/// Response for user list
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserListResponse {
    /// Whether the operation was successful
    pub success:    bool,
    /// List of users
    pub users:      Vec<UserProfileResponse>,
    /// Pagination info
    pub pagination: PaginationInfo,
}

/// Pagination information
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaginationInfo {
    /// Current page number (1-based)
    pub page:        u64,
    /// Items per page
    pub per_page:    u64,
    /// Total number of items
    pub total:       u64,
    /// Total number of pages
    pub total_pages: u64,
}

/// Query parameters for user list
#[derive(Debug, Clone, Deserialize)]
pub struct UserListQuery {
    /// Page number (1-based, default: 1)
    pub page:     Option<u64>,
    /// Items per page (default: 20, max: 100)
    pub per_page: Option<u64>,
    /// Search term for email/username/name
    pub search:   Option<String>,
    /// Filter by status
    pub status:   Option<String>,
}

impl UserListQuery {
    /// Get page number (1-based, default: 1)
    pub fn page(&self) -> u64 { self.page.unwrap_or(1).max(1) }

    /// Get items per page (default: 20, max: 100)
    pub fn per_page(&self) -> u64 { self.per_page.unwrap_or(20).clamp(1, 100) }
}
