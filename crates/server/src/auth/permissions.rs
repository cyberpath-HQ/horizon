//! # Permission Service
//!
//! Flexible permission system that checks permissions optionally via roles,
//! supports role inheritance, and handles permission scopes.

use std::collections::HashSet;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tracing::debug;
use error::Result;

/// Represents a single permission
///
/// Permissions should follow a hierarchical naming convention:
/// - Format: `resource:action`
/// - Examples: `users:create`, `teams:read`, `api_keys:delete`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// Resource being operated on (e.g., "users", "teams", "assets")
    pub resource: String,
    /// Action being performed (e.g., "create", "read", "update", "delete")
    pub action:   String,
}

impl Permission {
    /// Create a new permission from resource and action
    #[must_use]
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action:   action.into(),
        }
    }

    /// Create a permission string (e.g., "users:create")
    #[must_use]
    pub fn as_string(&self) -> String { format!("{}:{}", self.resource, self.action) }

    /// Parse a permission string into a Permission struct
    #[must_use]
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            Some(Self::new(parts[0], parts[1]))
        }
        else {
            None
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
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
    /// let result = service.check_permission("user-123", Permission::new("users", "create")).await?;
    /// if matches!(result, PermissionCheckResult::Allowed) {
    ///     // User can create users
    /// }
    /// ```
    pub async fn check_permission(&self, user_id: &str, permission: Permission) -> Result<PermissionCheckResult> {
        // Get all roles for the user
        let roles = crate::auth::roles::get_user_roles(&self.db, user_id).await?;

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

    /// Get all permissions for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to get permissions for
    ///
    /// # Returns
    ///
    /// Returns a HashSet of all permissions the user has
    pub async fn get_user_permissions(&self, user_id: &str) -> Result<HashSet<String>> {
        let roles = crate::auth::roles::get_user_roles(&self.db, user_id).await?;

        let mut all_permissions = HashSet::new();

        for role_name in &roles {
            // Get the role from the database
            let role = entity::roles::Entity::find()
                .filter(entity::roles::Column::Slug.eq(role_name))
                .one(&self.db)
                .await?
                .ok_or_else(|| error::AppError::not_found(format!("Role '{}' not found", role_name)))?;

            // Parse role permissions from JSON
            let role_permissions: Vec<String> = serde_json::from_value(role.permissions.clone()).unwrap_or_default();

            for perm in role_permissions {
                all_permissions.insert(perm);
            }

            // Add inherited permissions
            let inherited = self.get_role_inheritance(&self.db, &role.id).await?;
            all_permissions.extend(inherited);
        }

        Ok(all_permissions)
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
        let roles = crate::auth::roles::get_user_roles(&self.db, user_id).await?;

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
    use sea_orm::{Database, DatabaseConnection};

    use super::*;

    async fn setup_test_db() -> DatabaseConnection {
        Database::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to test database")
    }

    #[tokio::test]
    async fn test_permission_new() {
        let perm = Permission::new("users", "create");
        assert_eq!(perm.resource, "users");
        assert_eq!(perm.action, "create");
    }

    #[tokio::test]
    async fn test_permission_from_string() {
        let perm = Permission::from_string("users:create").unwrap();
        assert_eq!(perm.resource, "users");
        assert_eq!(perm.action, "create");
    }

    #[tokio::test]
    async fn test_permission_as_string() {
        let perm = Permission::new("teams", "update");
        assert_eq!(perm.as_string(), "teams:update");
    }

    #[tokio::test]
    async fn test_permission_display() {
        let perm = Permission::new("assets", "delete");
        let display = format!("{}", perm);
        assert_eq!(display, "assets:delete");
    }
}
