//! # User Handlers
//!
//! HTTP request handlers for user management endpoints.

use axum::Json;
use chrono::Utc;
use entity::{
    sea_orm_active_enums::UserStatus,
    users::{Column as UserColumn, Entity as UsersEntity},
};
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use tracing::info;

use crate::{
    auth::roles::get_user_roles,
    dto::users::{PaginationInfo, UpdateUserProfileRequest, UserListQuery, UserListResponse, UserProfileResponse},
    middleware::auth::AuthenticatedUser,
    AppState,
};

/// Get the authenticated user's profile
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
///
/// # Returns
///
/// User profile response with roles, MFA status, and account details
pub async fn get_my_profile_handler(state: &AppState, user: AuthenticatedUser) -> Result<Json<UserProfileResponse>> {
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let roles = get_user_roles(&state.db, &db_user.id).await?;
    let profile = user_model_to_response(&db_user, roles);

    Ok(Json(profile))
}

/// Update the authenticated user's profile
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - Profile update request with optional fields
///
/// # Returns
///
/// Updated user profile response
pub async fn update_my_profile_handler(
    state: &AppState,
    user: AuthenticatedUser,
    req: UpdateUserProfileRequest,
) -> Result<Json<UserProfileResponse>> {
    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let mut active_model: entity::users::ActiveModel = db_user.into();

    if let Some(first_name) = req.first_name {
        active_model.first_name = Set(Some(first_name));
    }
    if let Some(last_name) = req.last_name {
        active_model.last_name = Set(Some(last_name));
    }
    if let Some(avatar_url) = req.avatar_url {
        active_model.avatar_url = Set(Some(avatar_url));
    }
    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated_user = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update profile: {}", e)))?;

    let roles = get_user_roles(&state.db, &updated_user.id).await?;
    let profile = user_model_to_response(&updated_user, roles);

    info!(user_id = %user.id, "User profile updated");

    Ok(Json(profile))
}

/// List all users with pagination and filtering (admin only)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware (must have admin or super_admin role)
/// * `query` - Query parameters for filtering and pagination
///
/// # Returns
///
/// Paginated user list response
pub async fn list_users_handler(
    state: &AppState,
    user: AuthenticatedUser,
    query: UserListQuery,
) -> Result<Json<UserListResponse>> {
    // Check permission using the permission service
    let permission_service = crate::auth::permissions::PermissionService::new(state.db.clone());
    let result = permission_service
        .check_permission(
            &user.id,
            crate::auth::permissions::Permission::new("users", "read"),
        )
        .await?;

    match result {
        crate::auth::permissions::PermissionCheckResult::Allowed => {
            // Permission granted, continue with handler logic
        },
        _ => {
            return Err(AppError::forbidden(
                "You do not have permission to list users",
            ));
        },
    }

    let page = query.page();
    let per_page = query.per_page();

    let mut base_query = UsersEntity::find().filter(UserColumn::DeletedAt.is_null());

    if let Some(ref search) = query.search {
        let search_pattern = format!("%{}%", search);
        base_query = base_query.filter(
            Condition::any()
                .add(UserColumn::Email.like(&search_pattern))
                .add(UserColumn::Username.like(&search_pattern))
                .add(UserColumn::FirstName.like(&search_pattern))
                .add(UserColumn::LastName.like(&search_pattern)),
        );
    }

    if let Some(ref status) = query.status {
        let user_status = match status.as_str() {
            "active" => Some(UserStatus::Active),
            "inactive" => Some(UserStatus::Inactive),
            "suspended" => Some(UserStatus::Suspended),
            "pending_verification" => Some(UserStatus::PendingVerification),
            _ => None,
        };
        if let Some(s) = user_status {
            base_query = base_query.filter(UserColumn::Status.eq(s));
        }
    }

    let total = base_query
        .clone()
        .count(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to count users: {}", e)))?;

    let total_pages = if total == 0 {
        0
    }
    else {
        (total + per_page - 1) / per_page
    };

    let users = base_query
        .order_by_asc(UserColumn::CreatedAt)
        .paginate(&state.db, per_page)
        .fetch_page(page.saturating_sub(1))
        .await
        .map_err(|e| AppError::database(format!("Failed to fetch users: {}", e)))?;

    let mut user_responses = Vec::with_capacity(users.len());
    for u in &users {
        let roles = get_user_roles(&state.db, &u.id).await.unwrap_or_default();
        user_responses.push(user_model_to_response(u, roles));
    }

    Ok(Json(UserListResponse {
        success:    true,
        users:      user_responses,
        pagination: PaginationInfo {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Convert a user entity model to a profile response DTO
///
/// # Arguments
///
/// * `user` - The user entity model from the database
/// * `roles` - The user's role names
///
/// # Returns
///
/// A `UserProfileResponse` DTO
fn user_model_to_response(user: &entity::users::Model, roles: Vec<String>) -> UserProfileResponse {
    UserProfileResponse {
        id: user.id.clone(),
        email: user.email.clone(),
        username: user.username.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
        avatar_url: user.avatar_url.clone(),
        status: format!("{:?}", user.status).to_lowercase(),
        mfa_enabled: user.mfa_enabled,
        roles,
        email_verified_at: user.email_verified_at.map(|dt| dt.to_string()),
        last_login_at: user.last_login_at.map(|dt| dt.to_string()),
        created_at: user.created_at.to_string(),
        updated_at: user.updated_at.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test user model
    fn make_test_user(id: &str, email: &str, status: UserStatus, mfa: bool) -> entity::users::Model {
        entity::users::Model {
            id: id.to_string(),
            email: email.to_string(),
            username: email.to_string(),
            password_hash: "hashed".to_string(),
            totp_secret: None,
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            avatar_url: None,
            status,
            email_verified_at: None,
            last_login_at: None,
            created_at: chrono::NaiveDateTime::default(),
            updated_at: chrono::NaiveDateTime::default(),
            deleted_at: None,
            backup_codes: None,
            failed_login_attempts: 0,
            locked_until: None,
            mfa_enabled: mfa,
        }
    }

    #[test]
    fn test_user_model_to_response_with_roles() {
        let user = make_test_user("usr_test123", "test@example.com", UserStatus::Active, false);
        let response = user_model_to_response(&user, vec!["admin".to_string()]);

        assert_eq!(response.id, "usr_test123");
        assert_eq!(response.email, "test@example.com");
        assert_eq!(response.username, "test@example.com");
        assert_eq!(response.roles, vec!["admin"]);
        assert!(!response.mfa_enabled);
        assert_eq!(response.first_name, Some("Test".to_string()));
        assert_eq!(response.last_name, Some("User".to_string()));
        assert_eq!(response.status, "active");
    }

    #[test]
    fn test_user_model_to_response_no_roles() {
        let user = make_test_user(
            "usr_test456",
            "user@example.com",
            UserStatus::Inactive,
            false,
        );
        let response = user_model_to_response(&user, vec![]);

        assert!(response.roles.is_empty());
        assert_eq!(response.status, "inactive");
    }

    #[test]
    fn test_user_model_to_response_mfa_enabled() {
        let user = make_test_user("usr_mfa", "mfa@example.com", UserStatus::Active, true);
        let response = user_model_to_response(&user, vec!["user".to_string()]);

        assert!(response.mfa_enabled);
    }

    #[test]
    fn test_user_model_to_response_suspended_status() {
        let user = make_test_user("usr_sus", "sus@example.com", UserStatus::Suspended, false);
        let response = user_model_to_response(&user, vec![]);

        assert_eq!(response.status, "suspended");
    }

    #[test]
    fn test_user_model_to_response_pending_verification() {
        let user = make_test_user(
            "usr_pend",
            "pend@example.com",
            UserStatus::PendingVerification,
            false,
        );
        let response = user_model_to_response(&user, vec![]);

        assert_eq!(response.status, "pendingverification");
    }

    #[test]
    fn test_user_model_to_response_no_optional_fields() {
        let mut user = make_test_user("usr_bare", "bare@example.com", UserStatus::Active, false);
        user.first_name = None;
        user.last_name = None;
        user.avatar_url = None;

        let response = user_model_to_response(&user, vec![]);

        assert!(response.first_name.is_none());
        assert!(response.last_name.is_none());
        assert!(response.avatar_url.is_none());
    }

    #[test]
    fn test_user_list_query_defaults() {
        let query = UserListQuery {
            page:     None,
            per_page: None,
            search:   None,
            status:   None,
        };

        assert_eq!(query.page(), 1);
        assert_eq!(query.per_page(), 20);
    }

    #[test]
    fn test_user_list_query_clamp() {
        let query = UserListQuery {
            page:     Some(0),
            per_page: Some(500),
            search:   None,
            status:   None,
        };

        assert_eq!(query.page(), 1);
        assert_eq!(query.per_page(), 100);
    }

    #[test]
    fn test_user_list_query_min_per_page() {
        let query = UserListQuery {
            page:     Some(5),
            per_page: Some(0),
            search:   None,
            status:   None,
        };

        assert_eq!(query.page(), 5);
        assert_eq!(query.per_page(), 1);
    }
}
