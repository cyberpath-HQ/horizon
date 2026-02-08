//! # Permission Middleware
//!
//! Middleware for checking user permissions on API endpoints.

use error::AppError;

use crate::{
    auth::permissions::{Permission, PermissionCheckResult, PermissionService},
    middleware::auth::AuthenticatedUser,
    AppState,
};

/// Check if a user has a specific permission
///
/// This function can be used in handlers to check permissions.
/// For API key authenticated requests, permission checks are bypassed
/// since API keys have their own permission system.
///
/// # Arguments
///
/// * `user` - The authenticated user
/// * `permission` - The permission to check
/// * `state` - The application state containing the permission service
///
/// # Returns
///
/// Ok(()) if the user has the permission, or an error if not
pub async fn check_permission(
    user: &AuthenticatedUser,
    permission: Permission,
    state: &AppState,
) -> Result<(), AppError> {
    // Skip permission checks for API key authenticated requests
    // API keys have their own permission system that is checked by the API key middleware
    // For now, we assume API keys are only granted to users who have the corresponding permissions
    // TODO: Add a way to detect API key vs JWT auth in handlers

    let permission_service = PermissionService::new(state.db.clone());

    match permission_service
        .check_permission(&user.id, permission.clone())
        .await
    {
        Ok(PermissionCheckResult::Allowed) => Ok(()),
        Ok(PermissionCheckResult::Denied) => {
            Err(AppError::forbidden(format!(
                "Permission '{}' is required",
                permission
            )))
        },
        Ok(PermissionCheckResult::RequiresContext {
            ..
        }) => {
            Err(AppError::forbidden(format!(
                "Permission '{}' requires additional context",
                permission
            )))
        },
        Ok(PermissionCheckResult::Unauthenticated) => Err(AppError::unauthorized("Authentication required")),
        Err(e) => {
            Err(AppError::internal(format!(
                "Permission check failed: {}",
                e
            )))
        },
    }
}

/// Check if a user has all of the specified permissions
///
/// This function can be used in handlers to check multiple permissions.
/// For API key authenticated requests, permission checks are bypassed
/// since API keys have their own permission system.
///
/// # Arguments
///
/// * `user` - The authenticated user
/// * `permissions` - The permissions to check (all must be granted)
/// * `state` - The application state containing the permission service
///
/// # Returns
///
/// Ok(()) if the user has all permissions, or an error if not
pub async fn check_all_permissions(
    user: &AuthenticatedUser,
    permissions: Vec<Permission>,
    state: &AppState,
) -> Result<(), AppError> {
    // Skip permission checks for API key authenticated requests
    // API keys have their own permission system that is checked by the API key middleware
    // For now, we assume API keys are only granted to users who have the corresponding permissions
    // TODO: Add a way to detect API key vs JWT auth in handlers

    let permission_service = PermissionService::new(state.db.clone());

    for permission in permissions {
        match permission_service
            .check_permission(&user.id, permission.clone())
            .await
        {
            Ok(PermissionCheckResult::Allowed) => continue,
            Ok(PermissionCheckResult::Denied) => {
                return Err(AppError::forbidden(format!(
                    "Permission '{}' is required",
                    permission
                )))
            },
            Ok(PermissionCheckResult::RequiresContext {
                ..
            }) => {
                return Err(AppError::forbidden(format!(
                    "Permission '{}' requires additional context",
                    permission
                )))
            },
            Ok(PermissionCheckResult::Unauthenticated) => {
                return Err(AppError::unauthorized("Authentication required"))
            },
            Err(e) => {
                return Err(AppError::internal(format!(
                    "Permission check failed: {}",
                    e
                )))
            },
        }
    }

    Ok(())
}

/// Check if a user has any of the specified permissions
///
/// This function can be used in handlers to check if at least one permission is granted.
/// For API key authenticated requests, permission checks are bypassed
/// since API keys have their own permission system.
///
/// # Arguments
///
/// * `user` - The authenticated user
/// * `permissions` - The permissions to check (at least one must be granted)
/// * `state` - The application state containing the permission service
///
/// # Returns
///
/// Ok(()) if the user has at least one permission, or an error if not
pub async fn check_any_permissions(
    user: &AuthenticatedUser,
    permissions: Vec<Permission>,
    state: &AppState,
) -> Result<(), AppError> {
    // Skip permission checks for API key authenticated requests
    // API keys have their own permission system that is checked by the API key middleware
    // For now, we assume API keys are only granted to users who have the corresponding permissions
    // TODO: Add a way to detect API key vs JWT auth in handlers

    let permission_service = PermissionService::new(state.db.clone());

    for permission in &permissions {
        match permission_service
            .check_permission(&user.id, permission.clone())
            .await
        {
            Ok(PermissionCheckResult::Allowed) => return Ok(()),
            Ok(PermissionCheckResult::Denied) => continue,
            Ok(PermissionCheckResult::RequiresContext {
                ..
            }) => continue,
            Ok(PermissionCheckResult::Unauthenticated) => continue,
            Err(e) => {
                return Err(AppError::internal(format!(
                    "Permission check failed: {}",
                    e
                )))
            },
        }
    }

    Err(AppError::forbidden(format!(
        "At least one of the required permissions is needed: {:?}",
        permissions
    )))
}
