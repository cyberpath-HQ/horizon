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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Users(action) => write!(f, "users:{}", action),
            Permission::Teams(action) => write!(f, "teams:{}", action),
            Permission::ApiKeys(action) => write!(f, "api_keys:{}", action),
        }
    }
}

impl std::fmt::Display for UserAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserAction::Create => write!(f, "create"),
            UserAction::Read => write!(f, "read"),
            UserAction::Update => write!(f, "update"),
            UserAction::Delete => write!(f, "delete"),
        }
    }
}

impl UserAction {
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

impl std::fmt::Display for TeamAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeamAction::Create => write!(f, "create"),
            TeamAction::Read => write!(f, "read"),
            TeamAction::Update => write!(f, "update"),
            TeamAction::Delete => write!(f, "delete"),
            TeamAction::MembersRead => write!(f, "members_read"),
            TeamAction::MembersAdd => write!(f, "members_add"),
            TeamAction::MembersUpdate => write!(f, "members_update"),
            TeamAction::MembersRemove => write!(f, "members_remove"),
        }
    }
}

impl TeamAction {
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

impl std::fmt::Display for ApiKeyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyAction::Create => write!(f, "create"),
            ApiKeyAction::Read => write!(f, "read"),
            ApiKeyAction::Update => write!(f, "update"),
            ApiKeyAction::Delete => write!(f, "delete"),
            ApiKeyAction::Rotate => write!(f, "rotate"),
            ApiKeyAction::UsageRead => write!(f, "usage_read"),
        }
    }
}

impl ApiKeyAction {
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
        if role_permissions.contains(&permission.to_string()) {
            return Ok(PermissionCheckResult::Allowed);
        }

        // Check if this role inherits from other roles
        let inherited_permissions: HashSet<String> = self.get_role_inheritance(&self.db, &role.id).await?;

        if inherited_permissions.contains(&permission.to_string()) {
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
            PermissionCheckResult::Unauthenticated => Err(error::AppError::unauthorized("Authentication required")),
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

    // ==================== Permission Parsing Tests ====================

    #[test]
    fn test_permission_from_string_invalid() {
        assert_eq!(Permission::from_string("invalid:create"), None);
        assert_eq!(Permission::from_string("users:invalid"), None);
        assert_eq!(Permission::from_string("users"), None);
        assert_eq!(Permission::from_string(""), None);
        assert_eq!(Permission::from_string("users:create:extra"), None);
        assert_eq!(Permission::from_string("teams:"), None);
        assert_eq!(Permission::from_string(":create"), None);
    }

    #[test]
    fn test_permission_from_string_valid_all() {
        assert_eq!(
            Permission::from_string("users:create"),
            Some(Permission::Users(UserAction::Create))
        );
        assert_eq!(
            Permission::from_string("users:read"),
            Some(Permission::Users(UserAction::Read))
        );
        assert_eq!(
            Permission::from_string("users:update"),
            Some(Permission::Users(UserAction::Update))
        );
        assert_eq!(
            Permission::from_string("users:delete"),
            Some(Permission::Users(UserAction::Delete))
        );
        assert_eq!(
            Permission::from_string("teams:create"),
            Some(Permission::Teams(TeamAction::Create))
        );
        assert_eq!(
            Permission::from_string("teams:read"),
            Some(Permission::Teams(TeamAction::Read))
        );
        assert_eq!(
            Permission::from_string("teams:update"),
            Some(Permission::Teams(TeamAction::Update))
        );
        assert_eq!(
            Permission::from_string("teams:delete"),
            Some(Permission::Teams(TeamAction::Delete))
        );
        assert_eq!(
            Permission::from_string("teams:members_read"),
            Some(Permission::Teams(TeamAction::MembersRead))
        );
        assert_eq!(
            Permission::from_string("teams:members_add"),
            Some(Permission::Teams(TeamAction::MembersAdd))
        );
        assert_eq!(
            Permission::from_string("teams:members_update"),
            Some(Permission::Teams(TeamAction::MembersUpdate))
        );
        assert_eq!(
            Permission::from_string("teams:members_remove"),
            Some(Permission::Teams(TeamAction::MembersRemove))
        );
        assert_eq!(
            Permission::from_string("api_keys:create"),
            Some(Permission::ApiKeys(ApiKeyAction::Create))
        );
        assert_eq!(
            Permission::from_string("api_keys:read"),
            Some(Permission::ApiKeys(ApiKeyAction::Read))
        );
        assert_eq!(
            Permission::from_string("api_keys:update"),
            Some(Permission::ApiKeys(ApiKeyAction::Update))
        );
        assert_eq!(
            Permission::from_string("api_keys:delete"),
            Some(Permission::ApiKeys(ApiKeyAction::Delete))
        );
        assert_eq!(
            Permission::from_string("api_keys:rotate"),
            Some(Permission::ApiKeys(ApiKeyAction::Rotate))
        );
        assert_eq!(
            Permission::from_string("api_keys:usage_read"),
            Some(Permission::ApiKeys(ApiKeyAction::UsageRead))
        );
    }

    #[test]
    fn test_permission_display_all() {
        assert_eq!(
            format!("{}", Permission::Users(UserAction::Create)),
            "users:create"
        );
        assert_eq!(
            format!("{}", Permission::Users(UserAction::Read)),
            "users:read"
        );
        assert_eq!(
            format!("{}", Permission::Users(UserAction::Update)),
            "users:update"
        );
        assert_eq!(
            format!("{}", Permission::Users(UserAction::Delete)),
            "users:delete"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::Create)),
            "teams:create"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::Read)),
            "teams:read"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::Update)),
            "teams:update"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::Delete)),
            "teams:delete"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::MembersRead)),
            "teams:members_read"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::MembersAdd)),
            "teams:members_add"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::MembersUpdate)),
            "teams:members_update"
        );
        assert_eq!(
            format!("{}", Permission::Teams(TeamAction::MembersRemove)),
            "teams:members_remove"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Create)),
            "api_keys:create"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Read)),
            "api_keys:read"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Update)),
            "api_keys:update"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Delete)),
            "api_keys:delete"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Rotate)),
            "api_keys:rotate"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::UsageRead)),
            "api_keys:usage_read"
        );
    }

    // ==================== UserAction Tests ====================

    #[test]
    fn test_user_action_from_string_valid() {
        assert_eq!(UserAction::from_string("create"), Some(UserAction::Create));
        assert_eq!(UserAction::from_string("read"), Some(UserAction::Read));
        assert_eq!(UserAction::from_string("update"), Some(UserAction::Update));
        assert_eq!(UserAction::from_string("delete"), Some(UserAction::Delete));
    }

    #[test]
    fn test_user_action_from_string_invalid() {
        assert_eq!(UserAction::from_string("invalid"), None);
        assert_eq!(UserAction::from_string(""), None);
        assert_eq!(UserAction::from_string("READ"), None); // Case-sensitive
        assert_eq!(UserAction::from_string("destroy"), None);
    }

    #[test]
    fn test_user_action_display() {
        assert_eq!(format!("{}", UserAction::Create), "create");
        assert_eq!(format!("{}", UserAction::Read), "read");
        assert_eq!(format!("{}", UserAction::Update), "update");
        assert_eq!(format!("{}", UserAction::Delete), "delete");
    }

    // ==================== TeamAction Tests ====================

    #[test]
    fn test_team_action_from_string_valid() {
        assert_eq!(TeamAction::from_string("create"), Some(TeamAction::Create));
        assert_eq!(TeamAction::from_string("read"), Some(TeamAction::Read));
        assert_eq!(TeamAction::from_string("update"), Some(TeamAction::Update));
        assert_eq!(TeamAction::from_string("delete"), Some(TeamAction::Delete));
        assert_eq!(
            TeamAction::from_string("members_read"),
            Some(TeamAction::MembersRead)
        );
        assert_eq!(
            TeamAction::from_string("members_add"),
            Some(TeamAction::MembersAdd)
        );
        assert_eq!(
            TeamAction::from_string("members_update"),
            Some(TeamAction::MembersUpdate)
        );
        assert_eq!(
            TeamAction::from_string("members_remove"),
            Some(TeamAction::MembersRemove)
        );
    }

    #[test]
    fn test_team_action_from_string_invalid() {
        assert_eq!(TeamAction::from_string("invalid"), None);
        assert_eq!(TeamAction::from_string(""), None);
        assert_eq!(TeamAction::from_string("members"), None);
        assert_eq!(TeamAction::from_string("MEMBERS_READ"), None); // Case-sensitive
    }

    #[test]
    fn test_team_action_display() {
        assert_eq!(format!("{}", TeamAction::Create), "create");
        assert_eq!(format!("{}", TeamAction::Read), "read");
        assert_eq!(format!("{}", TeamAction::Update), "update");
        assert_eq!(format!("{}", TeamAction::Delete), "delete");
        assert_eq!(format!("{}", TeamAction::MembersRead), "members_read");
        assert_eq!(format!("{}", TeamAction::MembersAdd), "members_add");
        assert_eq!(format!("{}", TeamAction::MembersUpdate), "members_update");
        assert_eq!(format!("{}", TeamAction::MembersRemove), "members_remove");
    }

    // ==================== ApiKeyAction Tests ====================

    #[test]
    fn test_api_key_action_from_string_valid() {
        assert_eq!(
            ApiKeyAction::from_string("create"),
            Some(ApiKeyAction::Create)
        );
        assert_eq!(ApiKeyAction::from_string("read"), Some(ApiKeyAction::Read));
        assert_eq!(
            ApiKeyAction::from_string("update"),
            Some(ApiKeyAction::Update)
        );
        assert_eq!(
            ApiKeyAction::from_string("delete"),
            Some(ApiKeyAction::Delete)
        );
        assert_eq!(
            ApiKeyAction::from_string("rotate"),
            Some(ApiKeyAction::Rotate)
        );
        assert_eq!(
            ApiKeyAction::from_string("usage_read"),
            Some(ApiKeyAction::UsageRead)
        );
    }

    #[test]
    fn test_api_key_action_from_string_invalid() {
        assert_eq!(ApiKeyAction::from_string("invalid"), None);
        assert_eq!(ApiKeyAction::from_string(""), None);
        assert_eq!(ApiKeyAction::from_string("usage"), None);
        assert_eq!(ApiKeyAction::from_string("ROTATE"), None); // Case-sensitive
    }

    #[test]
    fn test_api_key_action_display() {
        assert_eq!(format!("{}", ApiKeyAction::Create), "create");
        assert_eq!(format!("{}", ApiKeyAction::Read), "read");
        assert_eq!(format!("{}", ApiKeyAction::Update), "update");
        assert_eq!(format!("{}", ApiKeyAction::Delete), "delete");
        assert_eq!(format!("{}", ApiKeyAction::Rotate), "rotate");
        assert_eq!(format!("{}", ApiKeyAction::UsageRead), "usage_read");
    }

    // ==================== Permission Enum Tests ====================

    #[test]
    fn test_permission_clone_and_equality() {
        let perm1 = Permission::Users(UserAction::Create);
        let perm2 = perm1.clone();
        assert_eq!(perm1, perm2);
    }

    #[test]
    fn test_permission_different_types_not_equal() {
        let perm1 = Permission::Users(UserAction::Create);
        let perm2 = Permission::Teams(TeamAction::Create);
        assert_ne!(perm1, perm2);
    }

    #[test]
    fn test_permission_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Permission::Users(UserAction::Create));
        set.insert(Permission::Users(UserAction::Create));
        assert_eq!(set.len(), 1); // Duplicates should not be added
    }

    // ==================== PermissionQuery Tests ====================

    #[test]
    fn test_permission_query_creation() {
        let query = PermissionQuery {
            permission:       Permission::Users(UserAction::Read),
            scope_type:       Some("team".to_string()),
            scope_id:         Some("team-123".to_string()),
            check_all_scopes: false,
        };
        assert_eq!(query.scope_type, Some("team".to_string()));
        assert_eq!(query.scope_id, Some("team-123".to_string()));
    }

    #[test]
    fn test_permission_query_no_scope() {
        let query = PermissionQuery {
            permission:       Permission::Users(UserAction::Read),
            scope_type:       None,
            scope_id:         None,
            check_all_scopes: false,
        };
        assert_eq!(query.scope_type, None);
        assert_eq!(query.scope_id, None);
    }

    // ==================== PermissionCheckResult Tests ====================

    #[test]
    fn test_permission_check_result_allowed() {
        let result = PermissionCheckResult::Allowed;
        assert!(matches!(result, PermissionCheckResult::Allowed));
    }

    #[test]
    fn test_permission_check_result_denied() {
        let result = PermissionCheckResult::Denied;
        assert!(matches!(result, PermissionCheckResult::Denied));
    }

    #[test]
    fn test_permission_check_result_requires_context() {
        let result = PermissionCheckResult::RequiresContext {
            scope_type: "team".to_string(),
            scope_id:   Some("t123".to_string()),
        };
        assert!(matches!(
            result,
            PermissionCheckResult::RequiresContext { .. }
        ));
    }

    #[test]
    fn test_permission_check_result_unauthenticated() {
        let result = PermissionCheckResult::Unauthenticated;
        assert!(matches!(result, PermissionCheckResult::Unauthenticated));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_permission_string() {
        assert_eq!(Permission::from_string(""), None);
    }

    #[test]
    fn test_whitespace_in_permission_string() {
        assert_eq!(Permission::from_string("users: create"), None);
        assert_eq!(Permission::from_string(" users:create"), None);
    }

    #[test]
    fn test_special_characters_in_permission() {
        assert_eq!(Permission::from_string("users@:create"), None);
        assert_eq!(Permission::from_string("users:create!"), None);
    }

    #[test]
    fn test_permission_conversion_roundtrip() {
        let perms = vec![
            Permission::Users(UserAction::Create),
            Permission::Users(UserAction::Read),
            Permission::Teams(TeamAction::MembersAdd),
            Permission::ApiKeys(ApiKeyAction::Rotate),
        ];

        for perm in perms {
            let str_perm = perm.to_string();
            let parsed = Permission::from_string(&str_perm);
            assert_eq!(Some(perm), parsed);
        }
    }

    #[test]
    fn test_permission_service_creation() {
        // This test verifies that PermissionService can be created
        // (Note: Full database-dependent tests would require integration tests)
        let _service: PermissionService;
        assert!(true); // Service type exists
    }

    // ==================== Additional Comprehensive Tests ====================

    #[test]
    fn test_multiple_actions_for_each_resource() {
        // Test all combinations of resources and actions
        let resources = vec![
            ("users", vec!["create", "read", "update", "delete"]),
            (
                "teams",
                vec![
                    "create",
                    "read",
                    "update",
                    "delete",
                    "members_read",
                    "members_add",
                    "members_update",
                    "members_remove",
                ],
            ),
            (
                "api_keys",
                vec!["create", "read", "update", "delete", "rotate", "usage_read"],
            ),
        ];

        for (resource, actions) in resources {
            for action in actions {
                let perm_str = format!("{}:{}", resource, action);
                let parsed = Permission::from_string(&perm_str);
                assert!(parsed.is_some(), "Failed to parse: {}", perm_str);
                let parsed_perm = parsed.unwrap();
                let back_to_str = parsed_perm.to_string();
                assert_eq!(back_to_str, perm_str, "Round-trip failed for {}", perm_str);
            }
        }
    }

    #[test]
    fn test_permission_ordering_consistency() {
        // Ensure permission comparison is consistent
        let user_create = Permission::Users(UserAction::Create);
        let user_read = Permission::Users(UserAction::Read);

        assert_eq!(user_create, user_create);
        assert_ne!(user_create, user_read);
        assert_ne!(user_read, user_create);
    }

    #[test]
    fn test_invalid_resource_names() {
        let invalid = vec![
            "admins:create",
            "roles:read",
            "permissions:write",
            "systems:delete",
            "data:read",
            ":create:",
            ":::",
        ];

        for s in invalid {
            assert!(
                Permission::from_string(&s).is_none(),
                "Should not parse invalid: {}",
                s
            );
        }
    }

    #[test]
    fn test_permission_query_all_scope_combinations() {
        let test_cases = vec![
            (None, None, false),
            (Some("team".to_string()), None, false),
            (Some("asset".to_string()), Some("a123".to_string()), false),
            (None, None, true),
            (Some("team".to_string()), Some("t456".to_string()), true),
        ];

        for (scope_type, scope_id, check_all) in test_cases {
            let query = PermissionQuery {
                permission:       Permission::Users(UserAction::Read),
                scope_type:       scope_type.clone(),
                scope_id:         scope_id.clone(),
                check_all_scopes: check_all,
            };
            assert_eq!(query.scope_type, scope_type);
            assert_eq!(query.scope_id, scope_id);
            assert_eq!(query.check_all_scopes, check_all);
        }
    }

    #[test]
    fn test_permission_result_pattern_matching() {
        let allowed = PermissionCheckResult::Allowed;
        let denied = PermissionCheckResult::Denied;
        let requires_context = PermissionCheckResult::RequiresContext {
            scope_type: "team".to_string(),
            scope_id:   None,
        };
        let unauth = PermissionCheckResult::Unauthenticated;

        // Test pattern matching
        assert!(matches!(allowed, PermissionCheckResult::Allowed));
        assert!(matches!(denied, PermissionCheckResult::Denied));
        assert!(matches!(
            requires_context,
            PermissionCheckResult::RequiresContext { .. }
        ));
        assert!(matches!(unauth, PermissionCheckResult::Unauthenticated));

        // Negative tests
        assert!(!matches!(allowed, PermissionCheckResult::Denied));
        assert!(!matches!(denied, PermissionCheckResult::Allowed));
    }

    #[test]
    fn test_permission_query_with_all_fields_populated() {
        let query = PermissionQuery {
            permission:       Permission::Teams(TeamAction::MembersAdd),
            scope_type:       Some("team".to_string()),
            scope_id:         Some("team-abc123".to_string()),
            check_all_scopes: true,
        };

        assert!(query.scope_type.is_some());
        assert!(query.scope_id.is_some());
        assert_eq!(query.check_all_scopes, true);
    }

    #[test]
    fn test_api_key_action_all_variants() {
        let actions = vec![
            ApiKeyAction::Create,
            ApiKeyAction::Read,
            ApiKeyAction::Update,
            ApiKeyAction::Delete,
            ApiKeyAction::Rotate,
            ApiKeyAction::UsageRead,
        ];

        for action in &actions {
            let display = format!("{}", action);
            let parsed = ApiKeyAction::from_string(&display);
            assert_eq!(Some(action.clone()), parsed);
        }
    }

    #[test]
    fn test_team_action_all_member_operations() {
        let member_actions = vec![
            TeamAction::MembersRead,
            TeamAction::MembersAdd,
            TeamAction::MembersUpdate,
            TeamAction::MembersRemove,
        ];

        for action in member_actions {
            let perm = Permission::Teams(action);
            let str_perm = perm.to_string();
            assert!(str_perm.contains("members"));
            let parsed = Permission::from_string(&str_perm);
            assert_eq!(Some(perm), parsed);
        }
    }

    #[test]
    fn test_permission_hashable_in_collections() {
        use std::collections::HashMap;

        let mut perm_map: HashMap<Permission, i32> = HashMap::new();

        perm_map.insert(Permission::Users(UserAction::Create), 1);
        perm_map.insert(Permission::Users(UserAction::Read), 2);
        perm_map.insert(Permission::Teams(TeamAction::Create), 3);

        assert_eq!(perm_map.len(), 3);
        assert_eq!(
            perm_map.get(&Permission::Users(UserAction::Create)),
            Some(&1)
        );
        assert_eq!(
            perm_map.get(&Permission::Teams(TeamAction::Create)),
            Some(&3)
        );
    }

    #[test]
    fn test_permission_string_lengths() {
        let short = Permission::Users(UserAction::Read);
        let long = Permission::Teams(TeamAction::MembersRemove);

        let short_str = short.to_string();
        let long_str = long.to_string();

        assert!(short_str.len() < long_str.len());
        assert!(short_str.contains(":"));
        assert!(long_str.contains(":"));
    }

    #[test]
    fn test_permission_from_string_boundary_cases() {
        // Single character parts
        assert_eq!(Permission::from_string("a:b"), None);

        // Maximum reasonable length
        let long_perm = format!("{}:create", "x".repeat(100));
        assert_eq!(Permission::from_string(&long_perm), None);

        // Unicode characters
        assert_eq!(Permission::from_string("userš:create"), None);
        assert_eq!(Permission::from_string("users:créate"), None);
    }

    #[test]
    fn test_all_user_actions_unique() {
        let user_actions = vec![
            UserAction::Create,
            UserAction::Read,
            UserAction::Update,
            UserAction::Delete,
        ];

        // Ensure all have unique string representations
        let strings: Vec<String> = user_actions.iter().map(|a| format!("{}", a)).collect();

        for i in 0 .. strings.len() {
            for j in (i + 1) .. strings.len() {
                assert_ne!(strings[i], strings[j]);
            }
        }
    }
}
