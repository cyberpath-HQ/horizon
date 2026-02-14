//! # User Handlers
//!
//! HTTP request handlers for user management endpoints.

use axum::Json;
use chrono::Utc;
use entity::{
    sea_orm_active_enums::{RoleScopeType, UserStatus},
    users::{Column as UserColumn, Entity as UsersEntity},
};
use error::{AppError, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use tracing::debug;
use auth::{
    permissions::{Permission, UserAction},
    roles::{assign_role_to_user, get_user_roles},
    secrecy::ExposeSecret,
};
use permissions_macro::with_permission;
use validator::Validate;

use crate::{
    dto::{
        auth::SuccessResponse,
        users::{
            PaginationInfo,
            UpdateUserProfileRequest,
            UpdateUserRequest,
            UserListQuery,
            UserListResponse,
            UserProfileResponse,
        },
    },
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
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    let db_user = UsersEntity::find_by_id(&user.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let mut active_model: entity::users::ActiveModel = db_user.into();

    if let Some(full_name) = req.full_name {
        active_model.full_name = Set(full_name);
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

    debug!(user_id = %user.id, "User profile updated");

    Ok(Json(profile))
}

/// Create a new user (requires users:create permission)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `req` - Request body with user details
///
/// # Returns
///
/// Created user profile response
#[with_permission(Permission::Users(UserAction::Create))]
pub async fn create_user_handler(
    state: &AppState,
    user: crate::middleware::auth::AuthenticatedUser,
    req: crate::dto::users::CreateUserRequest,
) -> Result<(axum::http::StatusCode, String)> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Check permissions
    // let permission_service = auth::permissions::PermissionService::new(state.db.clone());
    // permission_service
    //     .require_permission_for_roles(
    //         &user.roles,
    //         auth::permissions::Permission::Users(auth::permissions::UserAction::Create),
    //     )
    //     .await?;

    // Check if user already exists
    let existing = UsersEntity::find()
        .filter(UserColumn::Email.eq(&req.email))
        .one(&state.db)
        .await
        .map_err(|e| {
            AppError::Database {
                message: e.to_string(),
            }
        })?;

    if existing.is_some() {
        return Err(AppError::Conflict {
            message: "User with this email already exists".to_string(),
        });
    }

    // Hash the password
    let password_secret = auth::secrecy::SecretString::from(req.password);
    let hashed_password = auth::password::hash_password(&password_secret, None).map_err(|e| {
        AppError::Internal {
            message: format!("Failed to hash password: {}", e),
        }
    })?;

    // Create the user
    let new_user = entity::users::ActiveModel {
        email: Set(req.email.clone()),
        full_name: Set(req.full_name.clone()),
        password_hash: Set(hashed_password.expose_secret().to_string()),
        status: Set(UserStatus::Active),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    };

    let created_user = new_user.insert(&state.db).await.map_err(|e| {
        AppError::Database {
            message: e.to_string(),
        }
    })?;

    // Assign role if provided (default to "viewer" if not specified)
    let role_to_assign = req.role.as_deref().unwrap_or("viewer");
    assign_role_to_user(
        &state.db,
        &created_user.id,
        role_to_assign,
        RoleScopeType::Global,
        None,
        None,
    )
    .await
    .map_err(|e| {
        AppError::Database {
            message: format!("Failed to assign role: {}", e),
        }
    })?;

    // info!(user_id = %created_user.id, email = %req.email, "User created by {}", user.id);

    Ok((
        axum::http::StatusCode::CREATED,
        "User created successfully".to_string(),
    ))
}

/// List all users with pagination and filtering (admin only)
///
/// # Arguments
///
/// Paginated user list response
#[with_permission(Permission::Users(UserAction::Read))]
pub async fn list_users_handler(
    state: &AppState,
    user: AuthenticatedUser,
    query: UserListQuery,
) -> Result<Json<UserListResponse>> {
    // Check permissions
    // let permission_service = auth::permissions::PermissionService::new(state.db.clone());
    // permission_service
    //     .require_permission_for_roles(
    //         &user.roles,
    //         auth::permissions::Permission::Users(auth::permissions::UserAction::Create),
    //     )
    //     .await?;

    let page = query.page();
    let per_page = query.per_page();

    let mut base_query = UsersEntity::find().filter(UserColumn::DeletedAt.is_null());

    if let Some(ref search) = query.search {
        let search_pattern = format!("%{}%", search);
        base_query = base_query.filter(
            Condition::any()
                .add(UserColumn::Email.like(&search_pattern))
                .add(UserColumn::FullName.like(&search_pattern)),
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
        total.div_ceil(per_page)
    };

    let users = base_query
        .order_by_asc(UserColumn::CreatedAt)
        .paginate(&state.db, per_page)
        .fetch_page(page.saturating_sub(1))
        .await
        .map_err(|e| AppError::database(format!("Failed to fetch users: {}", e)))?;

    let mut user_responses = Vec::with_capacity(users.len());
    for u in &users {
        let roles = get_user_roles(&state.db, &u.id).await?;
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

/// Update a user by ID (admin only)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `user_id` - ID of the user to update
/// * `req` - Update request with optional fields
///
/// # Returns
///
/// Updated user profile response
#[with_permission(Permission::Users(UserAction::Update))]
pub async fn update_user_handler(
    state: &AppState,
    user: AuthenticatedUser,
    user_id: String,
    req: UpdateUserRequest,
) -> Result<Json<UserProfileResponse>> {
    // Validate request
    req.validate().map_err(|e| {
        AppError::Validation {
            message: e.to_string(),
        }
    })?;

    // Find the user to update
    let db_user = UsersEntity::find_by_id(&user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let mut active_model: entity::users::ActiveModel = db_user.into();

    // Update full_name if provided
    if let Some(full_name) = req.full_name {
        active_model.full_name = Set(full_name);
    }

    // Update status if provided
    if let Some(ref status) = req.status {
        let user_status = match status.as_str() {
            "active" => UserStatus::Active,
            "inactive" => UserStatus::Inactive,
            "suspended" => UserStatus::Suspended,
            "pending_verification" => UserStatus::PendingVerification,
            _ => {
                return Err(AppError::Validation {
                    message: format!("Invalid status: {}", status),
                });
            },
        };
        active_model.status = Set(user_status);
    }

    active_model.updated_at = Set(Utc::now().naive_utc());

    let updated_user = active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to update user: {}", e)))?;

    // Update role if provided
    if let Some(ref role) = req.role {
        // Delete all existing roles for this user
        entity::user_roles::Entity::delete_many()
            .filter(entity::user_roles::Column::UserId.eq(&updated_user.id))
            .exec(&state.db)
            .await
            .map_err(|e| AppError::database(format!("Failed to remove existing roles: {}", e)))?;

        // Assign new role
        auth::roles::assign_role_to_user(
            &state.db,
            &updated_user.id,
            role,
            RoleScopeType::Global,
            None,
            None,
        )
        .await
        .map_err(|e| AppError::database(format!("Failed to assign role: {}", e)))?;
    }

    let roles = get_user_roles(&state.db, &updated_user.id).await?;
    let profile = user_model_to_response(&updated_user, roles);

    debug!(user_id = %user_id, "User updated by admin");

    Ok(Json(profile))
}

/// Get a user by ID (admin only)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `user_id` - ID of the user to retrieve
///
/// # Returns
///
/// User profile response
#[with_permission(Permission::Users(UserAction::Read))]
pub async fn get_user_handler(
    state: &AppState,
    user: AuthenticatedUser,
    user_id: &str,
) -> Result<Json<UserProfileResponse>> {
    let db_user = UsersEntity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let roles = get_user_roles(&state.db, &db_user.id).await?;
    let profile = user_model_to_response(&db_user, roles);

    Ok(Json(profile))
}

/// Delete a user by ID (admin only)
///
/// # Arguments
///
/// * `state` - Application state
/// * `user` - Authenticated user from middleware
/// * `user_id` - ID of the user to delete
///
/// # Returns
///
/// Success response
#[with_permission(Permission::Users(UserAction::Delete))]
pub async fn delete_user_handler(
    state: &AppState,
    user: AuthenticatedUser,
    user_id: &str,
) -> Result<Json<SuccessResponse>> {
    // Find the user to delete
    let db_user = UsersEntity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    // Prevent deleting yourself
    if db_user.id == user.id {
        return Err(AppError::Validation {
            message: "Cannot delete your own account".to_string(),
        });
    }

    // Soft delete - set deleted_at timestamp
    let mut active_model: entity::users::ActiveModel = db_user.into();
    active_model.deleted_at = Set(Some(Utc::now().naive_utc()));
    active_model
        .update(&state.db)
        .await
        .map_err(|e| AppError::database(format!("Failed to delete user: {}", e)))?;

    debug!(user_id = %user_id, "User deleted by admin");

    Ok(Json(SuccessResponse {
        success: true,
        message: "User deleted successfully".to_string(),
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
        full_name: user.full_name.clone(),
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
            password_hash: "hashed".to_string(),
            totp_secret: None,
            full_name: "Test User".to_string(),
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
        assert_eq!(response.full_name, "Test User");
        assert_eq!(response.roles, vec!["admin"]);
        assert!(!response.mfa_enabled);
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
        let user = make_test_user("usr_bare", "bare@example.com", UserStatus::Active, false);

        let response = user_model_to_response(&user, vec![]);

        assert_eq!(response.full_name, "Test User");
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
