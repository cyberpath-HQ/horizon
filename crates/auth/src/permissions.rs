//! # Permission Service
//!
//! Flexible permission system that checks permissions optionally via roles,
//! supports role inheritance, and handles permission scopes.

use std::collections::HashSet;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tracing::debug;
use error::Result;

use crate::roles;

/// Represents a single permission
///
/// Permissions should follow a hierarchical naming convention:
/// - Format: `resource:action`
/// - Examples: `users:create`, `teams:read`, `api_keys:delete`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// User-related permissions
    Users(UserAction),
    /// Team-related permissions
    Teams(TeamAction),
    /// API key-related permissions
    ApiKeys(ApiKeyAction),
}

/// Actions available for user resources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserAction {
    /// Create new users
    Create,
    /// Read user information
    Read,
    /// Update user information
    Update,
    /// Delete users
    Delete,
}

/// Actions available for team resources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeamAction {
    /// Create new teams
    Create,
    /// Read team information
    Read,
    /// Update team information
    Update,
    /// Delete teams
    Delete,
    /// Read team members
    MembersRead,
    /// Add team members
    MembersAdd,
    /// Update team member roles
    MembersUpdate,
    /// Remove team members
    MembersRemove,
}

/// Actions available for API key resources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiKeyAction {
    /// Create API keys
    Create,
    /// Read API key information
    Read,
    /// Update API key permissions
    Update,
    /// Delete API keys
    Delete,
    /// Rotate API keys
    Rotate,
    /// Read API key usage
    UsageRead,
}

impl Permission {
    /// Create a permission string (e.g., "users:create")
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Permission::Users(action) => format!("users:{}", action.as_string()),
            Permission::Teams(action) => format!("teams:{}", action.as_string()),
            Permission::ApiKeys(action) => format!("api_keys:{}", action.as_string()),
        }
    }

    /// Parse a permission string into a Permission enum
    #[must_use]
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            match parts[0] {
                "users" => UserAction::from_string(parts[1]).map(Permission::Users),
                "teams" => TeamAction::from_string(parts[1]).map(Permission::Teams),
                "api_keys" => ApiKeyAction::from_string(parts[1]).map(Permission::ApiKeys),
                _ => None,
            }
        }
        else {
            None
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.as_string()) }
}

impl UserAction {
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            UserAction::Create => "create".to_string(),
            UserAction::Read => "read".to_string(),
            UserAction::Update => "update".to_string(),
            UserAction::Delete => "delete".to_string(),
        }
    }

    #[must_use]
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "create" => Some(UserAction::Create),
            "read" => Some(UserAction::Read),
            "update" => Some(UserAction::Update),
            "delete" => Some(UserAction::Delete),
            _ => None,
        }
    }
}

impl TeamAction {
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            TeamAction::Create => "create".to_string(),
            TeamAction::Read => "read".to_string(),
            TeamAction::Update => "update".to_string(),
            TeamAction::Delete => "delete".to_string(),
            TeamAction::MembersRead => "members_read".to_string(),
            TeamAction::MembersAdd => "members_add".to_string(),
            TeamAction::MembersUpdate => "members_update".to_string(),
            TeamAction::MembersRemove => "members_remove".to_string(),
        }
    }

    #[must_use]
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "create" => Some(TeamAction::Create),
            "read" => Some(TeamAction::Read),
            "update" => Some(TeamAction::Update),
            "delete" => Some(TeamAction::Delete),
            "members_read" => Some(TeamAction::MembersRead),
            "members_add" => Some(TeamAction::MembersAdd),
            "members_update" => Some(TeamAction::MembersUpdate),
            "members_remove" => Some(TeamAction::MembersRemove),
            _ => None,
        }
    }
}

impl ApiKeyAction {
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            ApiKeyAction::Create => "create".to_string(),
            ApiKeyAction::Read => "read".to_string(),
            ApiKeyAction::Update => "update".to_string(),
            ApiKeyAction::Delete => "delete".to_string(),
            ApiKeyAction::Rotate => "rotate".to_string(),
            ApiKeyAction::UsageRead => "usage_read".to_string(),
        }
    }

    #[must_use]
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "create" => Some(ApiKeyAction::Create),
            "read" => Some(ApiKeyAction::Read),
            "update" => Some(ApiKeyAction::Update),
            "delete" => Some(ApiKeyAction::Delete),
            "rotate" => Some(ApiKeyAction::Rotate),
            "usage_read" => Some(ApiKeyAction::UsageRead),
            _ => None,
        }
    }
}

/// Permission check result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionCheckResult {
    /// User has the permission
    Allowed,
    /// User doesn't have the permission
    Denied,
    /// Permission requires additional context (e.g., scope)
    RequiresContext {
        /// Required scope type
        scope_type: String,
        /// Scope ID that would be required
        scope_id:   Option<String>,
    },
    /// User is not authenticated
    Unauthenticated,
}

/// Permission query for scope-aware checks
#[derive(Debug, Clone)]
pub struct PermissionQuery {
    /// Permission to check
    pub permission:       Permission,
    /// Scope type to check (optional)
    pub scope_type:       Option<String>,
    /// Scope ID to check (optional)
    pub scope_id:         Option<String>,
    /// Check against all scopes or specific scope only
    pub check_all_scopes: bool,
}

/// Permission service for checking user permissions
#[derive(Clone, Debug)]
pub struct PermissionService {
    /// Database connection
    db: sea_orm::DbConn,
}

impl PermissionService {
    /// Create a new permission service
    #[must_use]
    pub fn new(db: sea_orm::DbConn) -> Self {
        Self {
            db,
        }
    }

    /// Check if a user has a specific permission
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to check permissions for
    /// * `permission` - The permission to check
    ///
    /// # Returns
    ///
    /// `PermissionCheckResult::Allowed` if the user has the permission,
    /// `PermissionCheckResult::Denied` otherwise
    ///
    /// # Example
    /// ```ignore
    /// let service = PermissionService::new(&db);
    /// let result = service.check_permission("user-123", Permission::Users(UserAction::Create)).await?;
    /// if matches!(result, PermissionCheckResult::Allowed) {
    ///     // User can create users
    /// }
    /// ```
    pub async fn check_permission(&self, user_id: &str, permission: Permission) -> Result<PermissionCheckResult> {
        // Get all roles for the user
        let roles = roles::get_user_roles(&self.db, user_id).await?;

        debug!(user_id = %user_id, permission = %permission, "Checking user permission");

        // Check each role's permissions
        for role_name in &roles {
            match self.check_role_permission(role_name, &permission).await? {
                PermissionCheckResult::Allowed => {
                    debug!(user_id = %user_id, role = %role_name, "Permission granted by role");
                    return Ok(PermissionCheckResult::Allowed);
                },
                PermissionCheckResult::Denied => {
                    // Continue checking other roles
                },
                PermissionCheckResult::RequiresContext {
                    scope_type,
                    scope_id,
                } => {
                    return Ok(PermissionCheckResult::RequiresContext {
                        scope_type,
                        scope_id,
                    });
                },
                PermissionCheckResult::Unauthenticated => {
                    return Ok(PermissionCheckResult::Unauthenticated);
                },
            }
        }

        debug!(user_id = %user_id, permission = %permission, "Permission denied");
        Ok(PermissionCheckResult::Denied)
    }

    /// Check if a role has a specific permission
    async fn check_role_permission(&self, role_name: &str, permission: &Permission) -> Result<PermissionCheckResult> {
        // Get the role from the database
        let role = entity::roles::Entity::find()
            .filter(entity::roles::Column::Slug.eq(role_name))
            .one(&self.db)
            .await?
            .ok_or_else(|| error::AppError::not_found(format!("Role '{}' not found", role_name)))?;

        // Parse role permissions from JSON
        let role_permissions: Vec<String> = serde_json::from_value(role.permissions.clone()).unwrap_or_default();

        // Check if the permission is directly granted by this role
        if role_permissions.contains(&permission.as_string()) {
            return Ok(PermissionCheckResult::Allowed);
        }

        // Check if this role inherits from other roles
        let inherited_permissions: HashSet<String> = self.get_role_inheritance(&self.db, &role.id).await?;

        if inherited_permissions.contains(&permission.as_string()) {
            return Ok(PermissionCheckResult::Allowed);
        }

        Ok(PermissionCheckResult::Denied)
    }

    /// Get all permissions inherited by a role
    async fn get_role_inheritance(&self, db: &sea_orm::DbConn, role_id: &str) -> Result<HashSet<String>> {
        let mut all_permissions = HashSet::new();
        let mut to_visit = vec![role_id.to_string()];

        while let Some(current_id) = to_visit.pop() {
            // Get direct permissions for this role
            let role = entity::roles::Entity::find()
                .filter(entity::roles::Column::Id.eq(&current_id))
                .one(db)
                .await?
                .ok_or_else(|| error::AppError::not_found(format!("Role '{}' not found", current_id)))?;

            let role_permissions: Vec<String> = serde_json::from_value(role.permissions.clone()).unwrap_or_default();

            for perm in role_permissions {
                all_permissions.insert(perm);
            }

            // Find roles that this role inherits from
            let inherits = entity::roles::Entity::find()
                .filter(entity::roles::Column::Slug.eq("inherits"))
                .one(db)
                .await?
                .ok_or_else(|| error::AppError::not_found("Role 'inherits' not found"))?;

            // Get all users who have this role
            let user_roles = entity::user_roles::Entity::find()
                .filter(entity::user_roles::Column::RoleId.eq(&role.id))
                .all(db)
                .await?;

            for user_role in user_roles {
                // Find the roles inherited by each user
                let inherits_user_roles = entity::user_roles::Entity::find()
                    .filter(entity::user_roles::Column::UserId.eq(&user_role.user_id))
                    .filter(
                        entity::user_roles::Column::ScopeType.eq(entity::sea_orm_active_enums::RoleScopeType::Global),
                    )
                    .all(db)
                    .await?;

                for inherits_role in inherits_user_roles {
                    if inherits_role.role_id == inherits.id {
                        // This user has the inherits role, so add all roles they have
                        let user_roles_for_inherits = entity::user_roles::Entity::find()
                            .filter(entity::user_roles::Column::UserId.eq(&user_role.user_id))
                            .all(db)
                            .await?;

                        for ur in user_roles_for_inherits {
                            if !to_visit.contains(&ur.role_id) {
                                to_visit.push(ur.role_id);
                            }
                        }
                    }
                }
            }
        }

        Ok(all_permissions)
    }

    /// Check if a user has any of the specified permissions
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to check permissions for
    /// * `permissions` - Permissions to check
    ///
    /// # Returns
    ///
    /// `PermissionCheckResult::Allowed` if the user has any of the permissions,
    /// `PermissionCheckResult::Denied` otherwise
    pub async fn check_any_permission(
        &self,
        user_id: &str,
        permissions: Vec<Permission>,
    ) -> Result<PermissionCheckResult> {
        for permission in permissions {
            match self.check_permission(user_id, permission).await? {
                PermissionCheckResult::Allowed => {
                    return Ok(PermissionCheckResult::Allowed);
                },
                PermissionCheckResult::RequiresContext {
                    ..
                } => {
                    return Ok(PermissionCheckResult::RequiresContext {
                        scope_type: String::new(),
                        scope_id:   None,
                    });
                },
                PermissionCheckResult::Unauthenticated => {
                    return Ok(PermissionCheckResult::Unauthenticated);
                },
                PermissionCheckResult::Denied => {
                    // Continue checking other permissions
                },
            }
        }
        Ok(PermissionCheckResult::Denied)
    }

    /// Check if a user has all of the specified permissions
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to check permissions for
    /// * `permissions` - Permissions to check
    ///
    /// # Returns
    ///
    /// `PermissionCheckResult::Allowed` if the user has all permissions,
    /// `PermissionCheckResult::Denied` otherwise
    pub async fn check_all_permissions(
        &self,
        user_id: &str,
        permissions: Vec<Permission>,
    ) -> Result<PermissionCheckResult> {
        for permission in permissions {
            match self.check_permission(user_id, permission).await? {
                PermissionCheckResult::Allowed => {
                    // Continue checking other permissions
                },
                PermissionCheckResult::RequiresContext {
                    ..
                } => {
                    return Ok(PermissionCheckResult::RequiresContext {
                        scope_type: String::new(),
                        scope_id:   None,
                    });
                },
                PermissionCheckResult::Unauthenticated => {
                    return Ok(PermissionCheckResult::Unauthenticated);
                },
                PermissionCheckResult::Denied => {
                    return Ok(PermissionCheckResult::Denied);
                },
            }
        }
        Ok(PermissionCheckResult::Allowed)
    }

    /// Check if a user has a permission and return an error if not
    ///
    /// This is a convenience method that checks a permission and returns
    /// a forbidden error if the user doesn't have it. This reduces boilerplate
    /// in handlers.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to check permissions for
    /// * `permission` - The permission to check
    ///
    /// # Returns
    ///
    /// `Ok(())` if the user has the permission, `Err(AppError)` otherwise
    ///
    /// # Example
    /// ```ignore
    /// permission_service.require_permission(&user.id, Permission::Users(UserAction::Read)).await?;
    /// // Continue with handler logic
    /// ```
    pub async fn require_permission(&self, user_id: &str, permission: Permission) -> Result<()> {
        match self.check_permission(user_id, permission).await? {
            PermissionCheckResult::Allowed => Ok(()),
            _ => Err(error::AppError::forbidden("Insufficient permissions")),
        }
    }

    /// Check if a user has a scoped permission (e.g., `teams:read` for team ID `t123`)
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to check permissions for
    /// * `permission` - The permission to check
    /// * `scope_type` - The scope type (e.g., "team", "asset")
    /// * `scope_id` - The scope ID
    ///
    /// # Returns
    ///
    /// `PermissionCheckResult::Allowed` if the user has the permission for the scope,
    /// `PermissionCheckResult::Denied` otherwise
    pub async fn check_scoped_permission(
        &self,
        user_id: &str,
        permission: Permission,
        scope_type: entity::sea_orm_active_enums::RoleScopeType,
        scope_id: &str,
    ) -> Result<PermissionCheckResult> {
        // Get all roles for the user
        let roles = roles::get_user_roles(&self.db, user_id).await?;

        // Check for roles with matching scope
        for role_name in &roles {
            // Find user-role assignments with matching scope
            let user_role_assignments = entity::user_roles::Entity::find()
                .filter(entity::user_roles::Column::RoleId.eq(role_name))
                .filter(entity::user_roles::Column::ScopeType.eq(scope_type.clone()))
                .filter(entity::user_roles::Column::ScopeId.eq(scope_id))
                .all(&self.db)
                .await?;

            if !user_role_assignments.is_empty() {
                // User has this role for this scope, check the permission
                match self.check_role_permission(role_name, &permission).await? {
                    PermissionCheckResult::Allowed => {
                        return Ok(PermissionCheckResult::Allowed);
                    },
                    PermissionCheckResult::Denied => {
                        // Continue checking other roles
                    },
                    _ => {
                        return Ok(PermissionCheckResult::Denied);
                    },
                }
            }
        }

        Ok(PermissionCheckResult::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_permission_new() {
        let perm = Permission::Users(UserAction::Create);
        assert_eq!(perm.as_string(), "users:create");
    }

    #[tokio::test]
    async fn test_permission_from_string() {
        let perm = Permission::from_string("users:create").unwrap();
        assert_eq!(perm, Permission::Users(UserAction::Create));
    }

    #[tokio::test]
    async fn test_permission_as_string() {
        let perm = Permission::Teams(TeamAction::Update);
        assert_eq!(perm.as_string(), "teams:update");
    }

    #[tokio::test]
    async fn test_permission_display() {
        let perm = Permission::ApiKeys(ApiKeyAction::Delete);
        let display = format!("{}", perm);
        assert_eq!(display, "api_keys:delete");
    }

    #[tokio::test]
    async fn test_user_action_from_string() {
        assert_eq!(UserAction::from_string("read"), Some(UserAction::Read));
        assert_eq!(UserAction::from_string("update"), Some(UserAction::Update));
        assert_eq!(UserAction::from_string("delete"), Some(UserAction::Delete));
        assert_eq!(UserAction::from_string("invalid"), None);
    }

    #[tokio::test]
    async fn test_team_action_from_string() {
        assert_eq!(TeamAction::from_string("create"), Some(TeamAction::Create));
        assert_eq!(
            TeamAction::from_string("members_read"),
            Some(TeamAction::MembersRead)
        );
        assert_eq!(TeamAction::from_string("invalid"), None);
    }

    #[tokio::test]
    async fn test_api_key_action_from_string() {
        assert_eq!(
            ApiKeyAction::from_string("create"),
            Some(ApiKeyAction::Create)
        );
        assert_eq!(
            ApiKeyAction::from_string("rotate"),
            Some(ApiKeyAction::Rotate)
        );
        assert_eq!(ApiKeyAction::from_string("invalid"), None);
    }
}
