//! # Role Service
//!
//! Handles loading and managing user roles from the database.

use entity::{roles::Entity as RolesEntity, sea_orm_active_enums::RoleScopeType, user_roles::Entity as UserRoleEntity};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use tracing::info;

/// Load roles for a specific user
///
/// Queries the user_roles table for the given user ID, joins with the roles table
/// to get role names, and filters out expired roles.
///
/// # Arguments
///
/// * `db` - Database connection
/// * `user_id` - The user ID to load roles for
///
/// # Returns
///
/// Returns `Ok(Vec<String>)` with the role names, or `Err(AppError)` for database errors.
///
/// # Example
/// ```ignore
/// let roles = get_user_roles(&db, user_id).await?;
/// ```
pub async fn get_user_roles(db: &DatabaseConnection, user_id: Uuid) -> crate::Result<Vec<String>> {
    use sea_orm::sea_query::Condition;
    use entity::user_roles::Column;

    info!(user_id = %user_id, "Loading user roles from database");

    // Find all active user role assignments for this user
    let now = chrono::Utc::now();
    let active_user_roles = UserRoleEntity::find()
        .filter(Column::UserId.eq(user_id))
        .filter(
            Condition::any()
                .add(Column::ExpiresAt.is_null())
                .add(Column::ExpiresAt.gt(now.naive_utc())),
        )
        .find_also_related(RolesEntity)
        .all(db)
        .await?;

    // Extract role names from the joined results
    let role_names: Vec<String> = active_user_roles
        .into_iter()
        .filter_map(|(_, role): (_, Option<_>)| role.map(|role| role.name.clone()))
        .collect();

    if role_names.is_empty() {
        // For users without explicit roles, assign a default role
        info!(
            user_id = %user_id,
            "User has no roles, assigning default role"
        );
        return Ok(vec!["user".to_string()]);
    }

    info!(
        user_id = %user_id,
        roles = ?role_names,
        "Successfully loaded user roles"
    );

    Ok(role_names)
}

/// Assign a role to a user
///
/// # Arguments
///
/// * `db` - Database connection
/// * `user_id` - The user ID to assign role to
/// * `role_slug` - The slug of the role to assign (e.g., "super_admin")
/// * `scope_type` - The scope type for this role assignment (global, team, asset)
/// * `scope_id` - Optional scope ID for scoped roles
/// * `expires_at` - Optional expiration date for temporary role assignments
///
/// # Errors
///
/// Returns an error if:
/// - The role doesn't exist
/// - The user_id is invalid
/// - Database operations fail
pub async fn assign_role_to_user(
    db: &DatabaseConnection,
    user_id: Uuid,
    role_slug: &str,
    scope_type: RoleScopeType,
    scope_id: Option<Uuid>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> crate::Result<()> {
    // Find the role by slug
    let role = RolesEntity::find()
        .filter(entity::roles::Column::Slug.eq(role_slug))
        .one(db)
        .await?
        .ok_or_else(|| {
            crate::AppError::Database {
                message: format!("Role '{}' not found", role_slug),
            }
        })?;

    // Create user role assignment
    let active_model = entity::user_roles::ActiveModel {
        id: Default::default(), // Auto-generated UUID
        user_id: Set(user_id),
        role_id: Set(role.id),
        scope_type: Set(scope_type),
        scope_id: Set(scope_id),
        expires_at: Set(expires_at.map(|dt| dt.naive_utc())),
        ..Default::default()
    };

    // Insert into database
    active_model.insert(db).await.map_err(|e| {
        crate::AppError::Database {
            message: format!("Failed to assign role to user: {}", e),
        }
    })?;

    info!(
        user_id = %user_id,
        role_name = %role.name,
        "Successfully assigned role to user"
    );

    Ok(())
}
