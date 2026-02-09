//! Integration tests for team permission checking
//!
//! These tests require a PostgreSQL database to be running with the schema initialized.
//! Set DATABASE_URL environment variable (defaults to local development database).

use sea_orm::{ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set};
use entity::{
    sea_orm_active_enums::{TeamMemberRole, UserStatus},
    team_members::{self, Column as MemberColumn},
    teams::{self},
    users::{self},
};
use server::{auth::teams::can_manage_team, middleware::auth::AuthenticatedUser, AppState};
use auth::JwtConfig;

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

/// Helper to create test AppState
async fn create_test_app_state(db: &DatabaseConnection) -> AppState {
    // Create a test Redis client (will use a test database)
    let redis_client = redis::Client::open("redis://127.0.0.1:6379").expect("Failed to create Redis client");

    // Create a test JWT config
    let jwt_config = JwtConfig {
        secret:             "test_jwt_secret_for_testing_only".to_string(),
        expiration_seconds: 3600,
        issuer:             "horizon-test".to_string(),
        audience:           "horizon-test-users".to_string(),
    };

    AppState {
        db: db.clone(),
        jwt_config,
        redis: redis_client,
        start_time: std::time::Instant::now(),
    }
}

/// Create a test user and return the AuthenticatedUser
async fn create_test_user(db: &DatabaseConnection, prefix: &str, counter: &mut u32) -> AuthenticatedUser {
    let email = unique_email(prefix, counter);
    let username = unique_username(prefix, counter);

    let user = users::ActiveModel {
        email: Set(email.clone()),
        username: Set(username),
        password_hash: Set("hashed_password".to_string()),
        status: Set(UserStatus::Active),
        mfa_enabled: Set(false),
        ..Default::default()
    };

    let created_user = user.insert(db).await.expect("Failed to create test user");

    AuthenticatedUser {
        id: created_user.id,
        email,
        roles: vec!["member".to_string()], // Default role
    }
}

/// Create a test team with a manager
async fn create_test_team(
    db: &DatabaseConnection,
    manager: &AuthenticatedUser,
    prefix: &str,
    counter: &mut u32,
) -> teams::Model {
    let team = teams::ActiveModel {
        name: Set(format!("Test Team {}", counter)),
        slug: Set(format!("test-team-{}-{}", prefix, counter)),
        description: Set(Some("Test team for permissions".to_string())),
        manager_id: Set(manager.id.clone()),
        ..Default::default()
    };

    team.insert(db).await.expect("Failed to create test team")
}

/// Add a user as a team member with specified role
async fn add_team_member(db: &DatabaseConnection, team_id: &str, user: &AuthenticatedUser, role: TeamMemberRole) {
    let member = team_members::ActiveModel {
        team_id: Set(team_id.to_string()),
        user_id: Set(user.id.clone()),
        role: Set(role),
        ..Default::default()
    };

    member.insert(db).await.expect("Failed to add team member");
}

#[tokio::test]
async fn test_admin_can_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create an admin user
    let mut admin_user = create_test_user(&db, "admin", &mut counter).await;
    admin_user.roles = vec!["admin".to_string()];

    // Create a team with a different manager
    let manager = create_test_user(&db, "manager", &mut counter).await;
    let team = create_test_team(&db, &manager, "admin_test", &mut counter).await;

    // Admin should be able to manage any team
    let can_manage = can_manage_team(&state, &admin_user, &team)
        .await
        .expect("Permission check should not error");

    assert!(can_manage, "Admin should be able to manage any team");

    // Cleanup
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&admin_user.id)
        .exec(&db)
        .await
        .expect("Failed to delete admin user");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
}

#[tokio::test]
async fn test_super_admin_can_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create a super admin user
    let mut super_admin = create_test_user(&db, "super_admin", &mut counter).await;
    super_admin.roles = vec!["super_admin".to_string()];

    // Create a team with a different manager
    let manager = create_test_user(&db, "manager", &mut counter).await;
    let team = create_test_team(&db, &manager, "super_admin_test", &mut counter).await;

    // Super admin should be able to manage any team
    let can_manage = can_manage_team(&state, &super_admin, &team)
        .await
        .expect("Permission check should not error");

    assert!(can_manage, "Super admin should be able to manage any team");

    // Cleanup
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&super_admin.id)
        .exec(&db)
        .await
        .expect("Failed to delete super admin user");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
}

#[tokio::test]
async fn test_team_manager_can_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create a manager user
    let manager = create_test_user(&db, "manager", &mut counter).await;

    // Create a team with this user as manager
    let team = create_test_team(&db, &manager, "manager_test", &mut counter).await;

    // Manager should be able to manage their own team
    let can_manage = can_manage_team(&state, &manager, &team)
        .await
        .expect("Permission check should not error");

    assert!(
        can_manage,
        "Team manager should be able to manage their own team"
    );

    // Cleanup
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
}

#[tokio::test]
async fn test_team_owner_member_can_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create a manager and an owner member
    let manager = create_test_user(&db, "manager", &mut counter).await;
    let owner_member = create_test_user(&db, "owner_member", &mut counter).await;

    // Create a team with the manager
    let team = create_test_team(&db, &manager, "owner_test", &mut counter).await;

    // Add the owner member to the team as an owner
    add_team_member(&db, &team.id, &owner_member, TeamMemberRole::Owner).await;

    // Owner member should be able to manage the team
    let can_manage = can_manage_team(&state, &owner_member, &team)
        .await
        .expect("Permission check should not error");

    assert!(
        can_manage,
        "Team owner member should be able to manage the team"
    );

    // Cleanup
    team_members::Entity::delete_many()
        .filter(MemberColumn::TeamId.eq(&team.id))
        .exec(&db)
        .await
        .expect("Failed to delete team members");
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
    users::Entity::delete_by_id(&owner_member.id)
        .exec(&db)
        .await
        .expect("Failed to delete owner member user");
}

#[tokio::test]
async fn test_non_owner_member_cannot_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create a manager and a regular member
    let manager = create_test_user(&db, "manager", &mut counter).await;
    let regular_member = create_test_user(&db, "regular_member", &mut counter).await;

    // Create a team with the manager
    let team = create_test_team(&db, &manager, "regular_test", &mut counter).await;

    // Add the regular member to the team as a member (not owner)
    add_team_member(&db, &team.id, &regular_member, TeamMemberRole::Member).await;

    // Regular member should NOT be able to manage the team
    let can_manage = can_manage_team(&state, &regular_member, &team)
        .await
        .expect("Permission check should not error");

    assert!(
        !can_manage,
        "Regular team member should not be able to manage the team"
    );

    // Cleanup
    team_members::Entity::delete_many()
        .filter(MemberColumn::TeamId.eq(&team.id))
        .exec(&db)
        .await
        .expect("Failed to delete team members");
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
    users::Entity::delete_by_id(&regular_member.id)
        .exec(&db)
        .await
        .expect("Failed to delete regular member user");
}

#[tokio::test]
async fn test_user_not_in_team_cannot_manage_team() {
    let db = get_test_db()
        .await
        .expect("Failed to connect to test database");
    let state = create_test_app_state(&db).await;
    let mut counter = 0;

    // Create a manager and a user not in the team
    let manager = create_test_user(&db, "manager", &mut counter).await;
    let outsider = create_test_user(&db, "outsider", &mut counter).await;

    // Create a team with the manager
    let team = create_test_team(&db, &manager, "outsider_test", &mut counter).await;

    // User not in team should NOT be able to manage the team
    let can_manage = can_manage_team(&state, &outsider, &team)
        .await
        .expect("Permission check should not error");

    assert!(
        !can_manage,
        "User not in team should not be able to manage the team"
    );

    // Cleanup
    teams::Entity::delete_by_id(&team.id)
        .exec(&db)
        .await
        .expect("Failed to delete team");
    users::Entity::delete_by_id(&manager.id)
        .exec(&db)
        .await
        .expect("Failed to delete manager user");
    users::Entity::delete_by_id(&outsider.id)
        .exec(&db)
        .await
        .expect("Failed to delete outsider user");
}
