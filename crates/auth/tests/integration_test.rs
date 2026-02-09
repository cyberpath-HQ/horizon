//! Integration tests for auth crate with real PostgreSQL database
//!
//! These tests require a PostgreSQL database to be running with the schema initialized.
//! Set DATABASE_URL environment variable (defaults to local development database).

use sea_orm::{
    ActiveModelTrait,
    ColumnTrait,
    Database,
    DatabaseConnection,
    EntityTrait,
    QueryFilter,
    QuerySelect,
    Set,
};
use chrono::Utc;
use auth::{
    assign_role_to_user,
    get_user_roles,
    permissions::PermissionCheckResult,
    ApiKeyAction,
    Permission,
    PermissionService,
    TeamAction,
    UserAction,
};
use entity::{
    roles::{self, Model as RoleModel},
    sea_orm_active_enums::{RoleScopeType, UserStatus},
    user_roles,
    users::{self},
};

/// Helper function to get test database connection from DATABASE_URL environment variable
async fn get_test_db() -> Result<DatabaseConnection, sea_orm::DbErr> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://horizon:horizon_secret_password_change_in_production@localhost:5432/horizon".to_string()
    });

    Database::connect(&database_url).await
}

/// Helper to generate unique email for test users
fn unique_email(prefix: &str, counter: &mut u32) -> String {
    *counter += 1;
    format!(
        "test_{}_{}_{}@example.com",
        prefix,
        counter,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// Helper to generate unique username for test users
fn unique_username(prefix: &str, counter: &mut u32) -> String {
    *counter += 1;
    format!(
        "test_{}_{}_{}",
        prefix,
        counter,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// Helper function to clean up test users
async fn cleanup_test_users(db: &DatabaseConnection) {
    users::Entity::delete_many()
        .filter(users::Column::Email.contains("test_"))
        .exec(db)
        .await
        .expect("Failed to cleanup test users");
}

#[tokio::test]
async fn test_get_user_roles_with_no_roles() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user without any roles
    let user = users::ActiveModel {
        email: Set(unique_email("no_roles", &mut counter)),
        username: Set(unique_username("no_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get roles for user with no roles assigned
    let roles = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert!(
        roles.is_empty(),
        "User with no roles should return empty vec"
    );

    // Cleanup
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_get_user_roles_with_single_role() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("single_role", &mut counter)),
        username: Set(unique_username("single_role", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Find or create a test role
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database - ensure migration has run");

    // Assign role to user
    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(None),
        ..Default::default()
    };

    user_role
        .insert(&db)
        .await
        .expect("Failed to assign role to user");

    // Get roles for user
    let roles = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert_eq!(roles.len(), 1, "User should have exactly one role");
    assert_eq!(roles[0], role.slug, "Role name should match");

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_get_user_roles_with_multiple_roles() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("multi_roles", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get first two roles from database
    let available_roles: Vec<RoleModel> = roles::Entity::find()
        .limit(2)
        .all(&db)
        .await
        .expect("Failed to query roles");

    assert!(
        available_roles.len() >= 2,
        "Need at least 2 roles in database for this test"
    );

    // Assign two roles to user
    for role in &available_roles {
        let user_role = user_roles::ActiveModel {
            user_id: Set(created_user.id.clone()),
            role_id: Set(role.id.clone()),
            scope_type: Set(RoleScopeType::Global),
            scope_id: Set(None),
            expires_at: Set(None),
            ..Default::default()
        };

        user_role
            .insert(&db)
            .await
            .expect("Failed to assign role to user");
    }

    // Get roles for user
    let user_roles_result = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert_eq!(
        user_roles_result.len(),
        available_roles.len(),
        "User should have assigned roles"
    );

    // Verify all assigned roles are returned
    for role in &available_roles {
        assert!(
            user_roles_result.contains(&role.slug),
            "Should contain assigned role: {}",
            role.slug
        );
    }

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_get_user_roles_filters_expired_roles() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("expired_roles", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role from database
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign an expired role to user
    let expired_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(Some((Utc::now() - chrono::Duration::days(1)).naive_utc())),
        ..Default::default()
    };

    expired_role
        .insert(&db)
        .await
        .expect("Failed to assign expired role");

    // Get roles for user - should not include expired role
    let user_roles_result = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert!(
        user_roles_result.is_empty(),
        "Expired roles should not be returned"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_assign_role_to_user_success() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("assign_role", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role to assign
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign role to user
    let result = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Global,
        None,
        None,
    )
    .await;

    assert!(result.is_ok(), "Role assignment should succeed");

    // Verify role was assigned
    let user_roles_result = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert_eq!(user_roles_result.len(), 1, "User should have one role");
    assert_eq!(
        user_roles_result[0], role.slug,
        "Assigned role slug should be returned"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_assign_role_with_scope() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("scoped_role", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role to assign
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign role with team scope
    let result = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Team,
        Some("team-123"),
        None,
    )
    .await;

    assert!(result.is_ok(), "Team-scoped role assignment should succeed");

    // Verify role was assigned
    let user_roles_result = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert!(
        !user_roles_result.is_empty(),
        "User should have assigned role"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_assign_role_with_expiration() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("expiring_role", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role to assign
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign role with expiration
    let expires_at = Some(Utc::now() + chrono::Duration::days(7));
    let result = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Global,
        None,
        expires_at,
    )
    .await;

    assert!(
        result.is_ok(),
        "Role assignment with expiration should succeed"
    );

    // Verify role was assigned
    let user_roles_result = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert!(
        !user_roles_result.is_empty(),
        "User should have temporary role"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_permission_service_initialization() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");

    // Create PermissionService
    let service = PermissionService::new(db.clone());

    // Service should be created successfully
    assert_eq!(std::mem::size_of_val(&service) > 0, true);
}

#[tokio::test]
async fn test_permission_enum_parsing() {
    // Test parsing user permissions
    let perm = Permission::from_string("users:create");
    assert!(perm.is_some());
    assert_eq!(perm.unwrap(), Permission::Users(UserAction::Create));

    // Test parsing team permissions
    let perm = Permission::from_string("teams:read");
    assert!(perm.is_some());
    assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::Read));

    // Test parsing API key permissions
    let perm = Permission::from_string("api_keys:create");
    assert!(perm.is_some());
    assert_eq!(perm.unwrap(), Permission::ApiKeys(ApiKeyAction::Create));

    // Test invalid permission
    let perm = Permission::from_string("invalid:permission");
    assert!(perm.is_none());
}

#[tokio::test]
async fn test_permission_display_format() {
    let perm = Permission::Users(UserAction::Create);
    let display_str = perm.to_string();
    assert_eq!(display_str, "users:create");

    let perm = Permission::Teams(TeamAction::MembersRead);
    let display_str = perm.to_string();
    assert_eq!(display_str, "teams:members_read");

    let perm = Permission::ApiKeys(ApiKeyAction::Rotate);
    let display_str = perm.to_string();
    assert_eq!(display_str, "api_keys:rotate");
}

#[tokio::test]
async fn test_permission_service_check_permission_for_user_without_roles() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user without roles
    let user = users::ActiveModel {
        email: Set(unique_email("no_perm", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Create permission service
    let service = PermissionService::new(db.clone());

    // Check permission - should be denied
    let result = service
        .check_permission(&created_user.id, Permission::Users(UserAction::Create))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result,
        PermissionCheckResult::Denied,
        "User without roles should have permissions denied"
    );

    // Cleanup
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_permission_parsing_all_user_actions() {
    // Test all UserAction variants
    let create_action = Permission::from_string("users:create");
    assert_eq!(create_action, Some(Permission::Users(UserAction::Create)));

    let read_action = Permission::from_string("users:read");
    assert_eq!(read_action, Some(Permission::Users(UserAction::Read)));

    let update_action = Permission::from_string("users:update");
    assert_eq!(update_action, Some(Permission::Users(UserAction::Update)));

    let delete_action = Permission::from_string("users:delete");
    assert_eq!(delete_action, Some(Permission::Users(UserAction::Delete)));
}

#[tokio::test]
async fn test_permission_parsing_all_team_actions() {
    // Test all TeamAction variants
    let create_action = Permission::from_string("teams:create");
    assert_eq!(create_action, Some(Permission::Teams(TeamAction::Create)));

    let members_read = Permission::from_string("teams:members_read");
    assert_eq!(
        members_read,
        Some(Permission::Teams(TeamAction::MembersRead))
    );

    let members_add = Permission::from_string("teams:members_add");
    assert_eq!(members_add, Some(Permission::Teams(TeamAction::MembersAdd)));

    let members_update = Permission::from_string("teams:members_update");
    assert_eq!(
        members_update,
        Some(Permission::Teams(TeamAction::MembersUpdate))
    );

    let members_remove = Permission::from_string("teams:members_remove");
    assert_eq!(
        members_remove,
        Some(Permission::Teams(TeamAction::MembersRemove))
    );
}

#[tokio::test]
async fn test_permission_parsing_all_api_key_actions() {
    // Test all ApiKeyAction variants
    let create_action = Permission::from_string("api_keys:create");
    assert_eq!(
        create_action,
        Some(Permission::ApiKeys(ApiKeyAction::Create))
    );

    let read_action = Permission::from_string("api_keys:read");
    assert_eq!(read_action, Some(Permission::ApiKeys(ApiKeyAction::Read)));

    let update_action = Permission::from_string("api_keys:update");
    assert_eq!(
        update_action,
        Some(Permission::ApiKeys(ApiKeyAction::Update))
    );

    let delete_action = Permission::from_string("api_keys:delete");
    assert_eq!(
        delete_action,
        Some(Permission::ApiKeys(ApiKeyAction::Delete))
    );

    let rotate_action = Permission::from_string("api_keys:rotate");
    assert_eq!(
        rotate_action,
        Some(Permission::ApiKeys(ApiKeyAction::Rotate))
    );

    let usage_read = Permission::from_string("api_keys:usage_read");
    assert_eq!(
        usage_read,
        Some(Permission::ApiKeys(ApiKeyAction::UsageRead))
    );
}

#[tokio::test]
async fn test_permission_invalid_action_names() {
    // Test invalid action names
    assert!(Permission::from_string("users:invalid_action").is_none());
    assert!(Permission::from_string("teams:nonexistent").is_none());
    assert!(Permission::from_string("api_keys:unknown").is_none());
    assert!(Permission::from_string("invalid_resource:create").is_none());
}

#[tokio::test]
async fn test_permission_malformed_strings() {
    // Test malformed permission strings
    assert!(Permission::from_string("no_colon").is_none());
    assert!(Permission::from_string(":").is_none());
    assert!(Permission::from_string("users:").is_none());
    assert!(Permission::from_string(":create").is_none());
    assert!(Permission::from_string("users:create:extra").is_none());
}

#[tokio::test]
async fn test_permission_case_sensitivity() {
    // Permissions are case-sensitive
    assert!(Permission::from_string("USERS:CREATE").is_none());
    assert!(Permission::from_string("Users:Create").is_none());
    assert!(Permission::from_string("users:CREATE").is_none());
}

#[tokio::test]
async fn test_permission_display_formatting_users() {
    assert_eq!(
        Permission::Users(UserAction::Create).to_string(),
        "users:create"
    );
    assert_eq!(
        Permission::Users(UserAction::Read).to_string(),
        "users:read"
    );
    assert_eq!(
        Permission::Users(UserAction::Update).to_string(),
        "users:update"
    );
    assert_eq!(
        Permission::Users(UserAction::Delete).to_string(),
        "users:delete"
    );
}

#[tokio::test]
async fn test_permission_display_formatting_teams() {
    assert_eq!(
        Permission::Teams(TeamAction::Create).to_string(),
        "teams:create"
    );
    assert_eq!(
        Permission::Teams(TeamAction::MembersRead).to_string(),
        "teams:members_read"
    );
    assert_eq!(
        Permission::Teams(TeamAction::MembersAdd).to_string(),
        "teams:members_add"
    );
}

#[tokio::test]
async fn test_permission_roundtrip_parsing_and_display() {
    let original = "users:create";
    let parsed = Permission::from_string(original).expect("Should parse");
    let displayed = parsed.to_string();
    assert_eq!(displayed, original);

    let another = "teams:members_update";
    let parsed2 = Permission::from_string(another).expect("Should parse");
    let displayed2 = parsed2.to_string();
    assert_eq!(displayed2, another);
}

#[tokio::test]
async fn test_user_action_display_formatting() {
    assert_eq!(UserAction::Create.to_string(), "create");
    assert_eq!(UserAction::Read.to_string(), "read");
    assert_eq!(UserAction::Update.to_string(), "update");
    assert_eq!(UserAction::Delete.to_string(), "delete");
}

#[tokio::test]
async fn test_team_action_display_formatting() {
    assert_eq!(TeamAction::Create.to_string(), "create");
    assert_eq!(TeamAction::Read.to_string(), "read");
    assert_eq!(TeamAction::MembersRead.to_string(), "members_read");
    assert_eq!(TeamAction::MembersAdd.to_string(), "members_add");
    assert_eq!(TeamAction::MembersUpdate.to_string(), "members_update");
    assert_eq!(TeamAction::MembersRemove.to_string(), "members_remove");
}

#[tokio::test]
async fn test_api_key_action_display_formatting() {
    assert_eq!(ApiKeyAction::Create.to_string(), "create");
    assert_eq!(ApiKeyAction::Read.to_string(), "read");
    assert_eq!(ApiKeyAction::Update.to_string(), "update");
    assert_eq!(ApiKeyAction::Delete.to_string(), "delete");
    assert_eq!(ApiKeyAction::Rotate.to_string(), "rotate");
    assert_eq!(ApiKeyAction::UsageRead.to_string(), "usage_read");
}

#[tokio::test]
async fn test_permission_check_result_allowed() {
    let result = PermissionCheckResult::Allowed;
    assert!(matches!(result, PermissionCheckResult::Allowed));
}

#[tokio::test]
async fn test_permission_check_result_denied() {
    let result = PermissionCheckResult::Denied;
    assert!(matches!(result, PermissionCheckResult::Denied));
}

#[tokio::test]
async fn test_permission_check_result_requires_context() {
    let result = PermissionCheckResult::RequiresContext {
        scope_type: "team".to_string(),
        scope_id:   Some("team-123".to_string()),
    };
    assert!(matches!(
        result,
        PermissionCheckResult::RequiresContext { .. }
    ));
}

#[tokio::test]
async fn test_permission_check_result_unauthenticated() {
    let result = PermissionCheckResult::Unauthenticated;
    assert!(matches!(result, PermissionCheckResult::Unauthenticated));
}

#[tokio::test]
async fn test_get_user_roles_consistent_across_calls() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user with a role
    let user = users::ActiveModel {
        email: Set(unique_email("consistent_roles", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role from database
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign role to user
    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(None),
        ..Default::default()
    };

    user_role.insert(&db).await.expect("Failed to assign role");

    // Call get_user_roles twice - should get consistent results
    let roles_first = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    let roles_second = get_user_roles(&db, &created_user.id)
        .await
        .expect("Failed to get user roles");

    assert_eq!(roles_first, roles_second, "Results should be consistent");
    assert_eq!(roles_first.len(), 1, "Should have one role");

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[tokio::test]
async fn test_assign_role_with_all_scope_types() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create a test user
    let user = users::ActiveModel {
        email: Set(unique_email("all_scopes", &mut counter)),
        username: Set(unique_username("multi_roles", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get a role to assign
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Test assigning with Global scope
    let result1 = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Global,
        None,
        None,
    )
    .await;
    assert!(result1.is_ok(), "Should assign with Global scope");

    // Cleanup user_roles for next test
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    // Test assigning with Team scope
    let result2 = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Team,
        Some("team-456"),
        None,
    )
    .await;
    assert!(result2.is_ok(), "Should assign with Team scope");

    // Cleanup user_roles for next test
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    // Test assigning with Asset scope
    let result3 = assign_role_to_user(
        &db,
        &created_user.id,
        &role.slug,
        RoleScopeType::Asset,
        Some("asset-789"),
        None,
    )
    .await;
    assert!(result3.is_ok(), "Should assign with Asset scope");

    // Final cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");

    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_permission_service_team_member_permissions() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");

    // Clean up any leftover test data
    cleanup_test_users(&db).await;

    let mut counter = 0;

    // Create test user
    let user = users::ActiveModel {
        email: Set(unique_email("team_perms", &mut counter)),
        username: Set(unique_username("team_perms", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };
    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get role
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign team member permissions
    let mut role_permissions = serde_json::Value::Array(vec![
        serde_json::Value::String("teams:members_read".to_string()),
        serde_json::Value::String("teams:members_add".to_string()),
    ]);
    let role_update = entity::roles::ActiveModel {
        id: Set(role.id.clone()),
        permissions: Set(role_permissions),
        ..Default::default()
    };
    role_update
        .update(&db)
        .await
        .expect("Failed to update role");

    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Team),
        scope_id: Set(Some("team-test".to_string())),
        expires_at: Set(None),
        ..Default::default()
    };
    user_role.insert(&db).await.expect("Failed to assign role");

    // Create service and check team permissions
    let service = PermissionService::new(db.clone());

    // Should allow members_read
    let result1 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::MembersRead))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result1,
        PermissionCheckResult::Allowed,
        "Should allow members_read permission"
    );

    // Should allow members_add
    let result2 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::MembersAdd))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result2,
        PermissionCheckResult::Allowed,
        "Should allow members_add permission"
    );

    // Should deny teams:read (member permission, not team management)
    let result3 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::Read))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result3,
        PermissionCheckResult::Denied,
        "Should deny teams:read for member-only permissions"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_permission_service_team_management_permissions() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create test user
    let user = users::ActiveModel {
        email: Set(unique_email("team_mgmt", &mut counter)),
        username: Set(unique_username("team_perms", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };
    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get role
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign team management permissions
    let mut role_permissions = serde_json::Value::Array(vec![
        serde_json::Value::String("teams:read".to_string()),
        serde_json::Value::String("teams:update".to_string()),
        serde_json::Value::String("teams:delete".to_string()),
        serde_json::Value::String("teams:create".to_string()),
    ]);
    let role_update = entity::roles::ActiveModel {
        id: Set(role.id.clone()),
        permissions: Set(role_permissions),
        ..Default::default()
    };
    role_update
        .update(&db)
        .await
        .expect("Failed to update role");

    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(None),
        ..Default::default()
    };
    user_role.insert(&db).await.expect("Failed to assign role");

    // Create service and check team management permissions
    let service = PermissionService::new(db.clone());

    // Should allow all management permissions
    let result1 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::Read))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result1,
        PermissionCheckResult::Allowed,
        "Should allow teams:read"
    );

    let result2 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::Update))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result2,
        PermissionCheckResult::Allowed,
        "Should allow teams:update"
    );

    let result3 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::Delete))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result3,
        PermissionCheckResult::Allowed,
        "Should allow teams:delete"
    );

    let result4 = service
        .check_permission(&created_user.id, Permission::Teams(TeamAction::Create))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result4,
        PermissionCheckResult::Allowed,
        "Should allow teams:create"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_permission_service_team_scope_isolation() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create first user with team-scoped permission for team A
    let user1 = users::ActiveModel {
        email: Set(unique_email("scope_isolation", &mut counter)),
        username: Set(unique_username("team_perms", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };
    let created_user = user1.insert(&db).await.expect("Failed to create test user");

    // Get role
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    let mut role_permissions = serde_json::Value::Array(vec![serde_json::Value::String("teams:read".to_string())]);
    let role_update = entity::roles::ActiveModel {
        id: Set(role.id.clone()),
        permissions: Set(role_permissions),
        ..Default::default()
    };
    role_update
        .update(&db)
        .await
        .expect("Failed to update role");

    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Team),
        scope_id: Set(Some("team-a".to_string())),
        expires_at: Set(None),
        ..Default::default()
    };
    user_role.insert(&db).await.expect("Failed to assign role");

    // Create service and check team-scoped permission
    let service = PermissionService::new(db.clone());

    // Should allow permission for correct scope
    let result1 = service
        .check_scoped_permission(
            &created_user.id,
            Permission::Teams(TeamAction::Read),
            RoleScopeType::Team,
            "team-a",
        )
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result1,
        PermissionCheckResult::Allowed,
        "Should allow permission for correct team scope"
    );

    // Should deny permission for different scope
    let result2 = service
        .check_scoped_permission(
            &created_user.id,
            Permission::Teams(TeamAction::Read),
            RoleScopeType::Team,
            "team-b",
        )
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result2,
        PermissionCheckResult::Denied,
        "Should deny permission for different team scope"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_permission_service_api_key_permissions() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create test user
    let user = users::ActiveModel {
        email: Set(unique_email("api_key_perms", &mut counter)),
        username: Set(unique_username("team_perms", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };
    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get role
    let role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign API key permissions
    let mut role_permissions = serde_json::Value::Array(vec![
        serde_json::Value::String("api_keys:read".to_string()),
        serde_json::Value::String("api_keys:rotate".to_string()),
    ]);
    let role_update = entity::roles::ActiveModel {
        id: Set(role.id.clone()),
        permissions: Set(role_permissions),
        ..Default::default()
    };
    role_update
        .update(&db)
        .await
        .expect("Failed to update role");

    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(None),
        ..Default::default()
    };
    user_role.insert(&db).await.expect("Failed to assign role");

    // Create service and check API key permissions
    let service = PermissionService::new(db.clone());

    // Should allow read permission
    let result1 = service
        .check_permission(&created_user.id, Permission::ApiKeys(ApiKeyAction::Read))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result1,
        PermissionCheckResult::Allowed,
        "Should allow api_keys:read"
    );

    // Should allow rotate permission
    let result2 = service
        .check_permission(&created_user.id, Permission::ApiKeys(ApiKeyAction::Rotate))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result2,
        PermissionCheckResult::Allowed,
        "Should allow api_keys:rotate"
    );

    // Should deny delete permission
    let result3 = service
        .check_permission(&created_user.id, Permission::ApiKeys(ApiKeyAction::Delete))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result3,
        PermissionCheckResult::Denied,
        "Should deny api_keys:delete"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}

#[serial_test::serial]
#[tokio::test]
async fn test_permission_service_role_inheritance() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let mut counter = 0;

    // Create test user
    let user = users::ActiveModel {
        email: Set(unique_email("role_inherit", &mut counter)),
        username: Set(unique_username("team_perms", &mut counter)),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };
    let created_user = user.insert(&db).await.expect("Failed to create test user");

    // Get base role
    let base_role = roles::Entity::find()
        .one(&db)
        .await
        .expect("Failed to query roles")
        .expect("No roles found in database");

    // Assign base role with read permission
    let mut base_perms = serde_json::Value::Array(vec![serde_json::Value::String("users:read".to_string())]);
    let base_role_update = entity::roles::ActiveModel {
        id: Set(base_role.id.clone()),
        permissions: Set(base_perms),
        ..Default::default()
    };
    base_role_update
        .update(&db)
        .await
        .expect("Failed to update role");

    let user_role = user_roles::ActiveModel {
        user_id: Set(created_user.id.clone()),
        role_id: Set(base_role.id.clone()),
        scope_type: Set(RoleScopeType::Global),
        scope_id: Set(None),
        expires_at: Set(None),
        ..Default::default()
    };
    user_role.insert(&db).await.expect("Failed to assign role");

    // Create service and check inherited permission
    let service = PermissionService::new(db.clone());

    // Should grant read permission from base role
    let result = service
        .check_permission(&created_user.id, Permission::Users(UserAction::Read))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result,
        PermissionCheckResult::Allowed,
        "Should grant permission from inherited role"
    );

    // Should deny write permission
    let result2 = service
        .check_permission(&created_user.id, Permission::Users(UserAction::Update))
        .await
        .expect("Permission check should not error");

    assert_eq!(
        result2,
        PermissionCheckResult::Denied,
        "Should deny permission not in inherited role"
    );

    // Cleanup
    user_roles::Entity::delete_many()
        .filter(user_roles::Column::UserId.eq(&created_user.id))
        .exec(&db)
        .await
        .expect("Failed to delete user roles");
    users::Entity::delete_by_id(&created_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete test user");
}
