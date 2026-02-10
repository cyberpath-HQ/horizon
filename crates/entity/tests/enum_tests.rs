//! Simple enum tests for entity crate
//! These tests avoid complex sea-orm async patterns that cause compilation issues

use entity::sea_orm_active_enums::{RoleScopeType, TeamMemberRole, UserStatus};

/// Test RoleScopeType enum values
#[test]
fn test_role_scope_type_values() {
    assert_eq!(format!("{}", RoleScopeType::Global), "global");
    assert_eq!(format!("{}", RoleScopeType::Team), "team");
    assert_eq!(format!("{}", RoleScopeType::Asset), "asset");
}

/// Test RoleScopeType equality
#[test]
fn test_role_scope_type_equality() {
    assert_eq!(RoleScopeType::Global, RoleScopeType::Global);
    assert_eq!(RoleScopeType::Team, RoleScopeType::Team);
    assert_eq!(RoleScopeType::Asset, RoleScopeType::Asset);
    assert_ne!(RoleScopeType::Global, RoleScopeType::Team);
}

/// Test TeamMemberRole enum values
#[test]
fn test_team_member_role_values() {
    assert_eq!(format!("{}", TeamMemberRole::Owner), "owner");
    assert_eq!(format!("{}", TeamMemberRole::Admin), "admin");
    assert_eq!(format!("{}", TeamMemberRole::Member), "member");
    assert_eq!(format!("{}", TeamMemberRole::Viewer), "viewer");
}

/// Test TeamMemberRole equality
#[test]
fn test_team_member_role_equality() {
    assert_eq!(TeamMemberRole::Owner, TeamMemberRole::Owner);
    assert_eq!(TeamMemberRole::Admin, TeamMemberRole::Admin);
    assert_ne!(TeamMemberRole::Owner, TeamMemberRole::Admin);
}

/// Test UserStatus enum values
#[test]
fn test_user_status_values() {
    assert_eq!(format!("{}", UserStatus::Active), "active");
    assert_eq!(format!("{}", UserStatus::Inactive), "inactive");
    assert_eq!(format!("{}", UserStatus::Suspended), "suspended");
    assert_eq!(
        format!("{}", UserStatus::PendingVerification),
        "pending_verification"
    );
}

/// Test UserStatus equality
#[test]
fn test_user_status_equality() {
    assert_eq!(UserStatus::Active, UserStatus::Active);
    assert_eq!(UserStatus::Inactive, UserStatus::Inactive);
    assert_ne!(UserStatus::Active, UserStatus::Suspended);
}

/// Test enum Clone
#[test]
fn test_enum_clone() {
    assert_eq!(RoleScopeType::Global.clone(), RoleScopeType::Global);
    assert_eq!(TeamMemberRole::Owner.clone(), TeamMemberRole::Owner);
    assert_eq!(UserStatus::Active.clone(), UserStatus::Active);
}

/// Test enum Debug
#[test]
fn test_enum_debug() {
    let debug = format!("{:?}", RoleScopeType::Global);
    assert!(debug.contains("Global"));

    let debug = format!("{:?}", TeamMemberRole::Owner);
    assert!(debug.contains("Owner"));

    let debug = format!("{:?}", UserStatus::Active);
    assert!(debug.contains("Active"));
}
