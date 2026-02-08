//! # Team Data Transfer Objects
//!
//! Request and response types for team management endpoints.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request to create a new team
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct CreateTeamRequest {
    /// Team name
    #[validate(length(
        min = 1,
        max = 255,
        message = "Team name must be between 1 and 255 characters"
    ))]
    pub name:           String,
    /// Team description
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    pub description:    Option<String>,
    /// Optional parent team ID for hierarchical teams
    pub parent_team_id: Option<String>,
}

/// Request to update an existing team
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct UpdateTeamRequest {
    /// Updated team name
    #[validate(length(
        min = 1,
        max = 255,
        message = "Team name must be between 1 and 255 characters"
    ))]
    pub name:        Option<String>,
    /// Updated description
    #[validate(length(max = 2000, message = "Description must not exceed 2000 characters"))]
    pub description: Option<String>,
    /// Updated manager user ID
    pub manager_id:  Option<String>,
}

/// Response for a single team
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamResponse {
    /// Team's unique identifier
    pub id:             String,
    /// Team name
    pub name:           String,
    /// URL-friendly slug
    pub slug:           String,
    /// Team description
    pub description:    Option<String>,
    /// Parent team ID for hierarchical teams
    pub parent_team_id: Option<String>,
    /// Manager user ID
    pub manager_id:     String,
    /// Number of members
    pub member_count:   Option<u64>,
    /// Creation timestamp
    pub created_at:     String,
    /// Last update timestamp
    pub updated_at:     String,
}

/// Response for team list
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamListResponse {
    /// Whether the operation was successful
    pub success:    bool,
    /// List of teams
    pub teams:      Vec<TeamResponse>,
    /// Pagination info
    pub pagination: super::users::PaginationInfo,
}

/// Request to add a member to a team
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct AddTeamMemberRequest {
    /// User ID to add
    #[validate(length(min = 1, message = "User ID is required"))]
    pub user_id: String,
    /// Role for the new member
    #[validate(length(min = 1, message = "Role is required"))]
    pub role:    String,
}

/// Request to update a team member's role
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
pub struct UpdateTeamMemberRequest {
    /// New role for the member
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

/// Response for a team member
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamMemberResponse {
    /// Team member record ID
    pub id:           String,
    /// User ID
    pub user_id:      String,
    /// User's email
    pub email:        String,
    /// User's display name
    pub display_name: String,
    /// Role in the team
    pub role:         String,
    /// When the user joined the team
    pub joined_at:    String,
}

/// Response for team members list
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamMembersResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Team members
    pub members: Vec<TeamMemberResponse>,
}

/// Query parameters for team list
#[derive(Debug, Clone, Deserialize)]
pub struct TeamListQuery {
    /// Page number (1-based, default: 1)
    pub page:     Option<u64>,
    /// Items per page (default: 20, max: 100)
    pub per_page: Option<u64>,
    /// Search term for name/slug
    pub search:   Option<String>,
}

impl TeamListQuery {
    /// Get page number (1-based, default: 1)
    pub fn page(&self) -> u64 { self.page.unwrap_or(1).max(1) }

    /// Get items per page (default: 20, max: 100)
    pub fn per_page(&self) -> u64 { self.per_page.unwrap_or(20).clamp(1, 100) }
}
