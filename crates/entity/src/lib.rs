#![recursion_limit = "16384"]
#![type_length_limit = "4194304"]
#![allow(
    clippy::all,
    reason = "Sea-ORM generated code with complex relationships requires this"
)]

//! Entity definitions for Horizon CMDB
//!
//! This crate contains Sea-ORM entity definitions for the database models.
//! Entities are auto-generated from the database schema.

pub mod api_keys;
pub use api_keys::Entity as ApiKeys;
pub mod api_key_usage_log;
pub use api_key_usage_log::Entity as ApiKeyUsageLog;
pub mod refresh_tokens;
pub use refresh_tokens::Entity as RefreshTokens;
pub mod roles;
pub use roles::Entity as Roles;
pub mod sea_orm_active_enums;
pub mod team_members;
pub use team_members::Entity as TeamMembers;
pub mod teams;
pub use teams::Entity as Teams;
pub mod user_roles;
pub use user_roles::Entity as UserRoles;
pub mod user_sessions;
pub use user_sessions::Entity as UserSessions;
pub mod users;
pub use users::Entity as Users;

#[cfg(test)]
mod entity_tests {
    use sea_orm::Iterable;
    use sea_orm_active_enums::{RoleScopeType, TeamMemberRole, UserStatus};

    use super::*;

    // ===== Tests for Active Enums =====

    #[test]
    fn test_role_scope_type_values() {
        // Test through Display trait since as_str requires IdenStatic
        assert_eq!(format!("{}", RoleScopeType::Global), "global");
        assert_eq!(format!("{}", RoleScopeType::Team), "team");
        assert_eq!(format!("{}", RoleScopeType::Asset), "asset");
    }

    #[test]
    fn test_role_scope_type_display() {
        assert_eq!(format!("{}", RoleScopeType::Global), "global");
        assert_eq!(format!("{}", RoleScopeType::Team), "team");
        assert_eq!(format!("{}", RoleScopeType::Asset), "asset");
    }

    #[test]
    fn test_role_scope_type_iteration() {
        let values: Vec<RoleScopeType> = RoleScopeType::iter().collect();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&RoleScopeType::Global));
        assert!(values.contains(&RoleScopeType::Team));
        assert!(values.contains(&RoleScopeType::Asset));
    }

    #[test]
    fn test_team_member_role_values() {
        assert_eq!(format!("{}", TeamMemberRole::Owner), "owner");
        assert_eq!(format!("{}", TeamMemberRole::Admin), "admin");
        assert_eq!(format!("{}", TeamMemberRole::Member), "member");
        assert_eq!(format!("{}", TeamMemberRole::Viewer), "viewer");
    }

    #[test]
    fn test_team_member_role_display() {
        assert_eq!(format!("{}", TeamMemberRole::Owner), "owner");
        assert_eq!(format!("{}", TeamMemberRole::Admin), "admin");
        assert_eq!(format!("{}", TeamMemberRole::Member), "member");
        assert_eq!(format!("{}", TeamMemberRole::Viewer), "viewer");
    }

    #[test]
    fn test_team_member_role_iteration() {
        let values: Vec<TeamMemberRole> = TeamMemberRole::iter().collect();
        assert_eq!(values.len(), 4);
        assert!(values.contains(&TeamMemberRole::Owner));
        assert!(values.contains(&TeamMemberRole::Admin));
        assert!(values.contains(&TeamMemberRole::Member));
        assert!(values.contains(&TeamMemberRole::Viewer));
    }

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

    #[test]
    fn test_user_status_display() {
        assert_eq!(format!("{}", UserStatus::Active), "active");
        assert_eq!(format!("{}", UserStatus::Inactive), "inactive");
        assert_eq!(format!("{}", UserStatus::Suspended), "suspended");
        assert_eq!(
            format!("{}", UserStatus::PendingVerification),
            "pending_verification"
        );
    }

    #[test]
    fn test_user_status_iteration() {
        let values: Vec<UserStatus> = UserStatus::iter().collect();
        assert_eq!(values.len(), 4);
        assert!(values.contains(&UserStatus::Active));
        assert!(values.contains(&UserStatus::Inactive));
        assert!(values.contains(&UserStatus::Suspended));
        assert!(values.contains(&UserStatus::PendingVerification));
    }

    // ===== Tests for Enum Equality =====

    #[test]
    fn test_role_scope_type_equality() {
        assert_eq!(RoleScopeType::Global, RoleScopeType::Global);
        assert_eq!(RoleScopeType::Team, RoleScopeType::Team);
        assert_eq!(RoleScopeType::Asset, RoleScopeType::Asset);
        assert_ne!(RoleScopeType::Global, RoleScopeType::Team);
    }

    #[test]
    fn test_team_member_role_equality() {
        assert_eq!(TeamMemberRole::Owner, TeamMemberRole::Owner);
        assert_ne!(TeamMemberRole::Owner, TeamMemberRole::Admin);
    }

    #[test]
    fn test_user_status_equality() {
        assert_eq!(UserStatus::Active, UserStatus::Active);
        assert_ne!(UserStatus::Active, UserStatus::Suspended);
    }

    // ===== Tests for Enum Clone =====

    #[test]
    fn test_role_scope_type_clone() {
        let original = RoleScopeType::Global;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_team_member_role_clone() {
        let original = TeamMemberRole::Owner;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_user_status_clone() {
        let original = UserStatus::Active;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ===== Tests for Enum Debug =====

    #[test]
    fn test_role_scope_type_debug() {
        let debug = format!("{:?}", RoleScopeType::Global);
        assert!(debug.contains("Global"));
    }

    #[test]
    fn test_team_member_role_debug() {
        let debug = format!("{:?}", TeamMemberRole::Owner);
        assert!(debug.contains("Owner"));
    }

    #[test]
    fn test_user_status_debug() {
        let debug = format!("{:?}", UserStatus::Active);
        assert!(debug.contains("Active"));
    }

    // ===== Tests for Entity Re-exports =====

    #[test]
    fn test_api_keys_type_exists() {
        // Just verify the types exist and are properly exported
        let _type: ApiKeys = ApiKeys;
    }

    #[test]
    fn test_api_key_usage_log_type_exists() { let _type: ApiKeyUsageLog = ApiKeyUsageLog; }

    #[test]
    fn test_refresh_tokens_type_exists() { let _type: RefreshTokens = RefreshTokens; }

    #[test]
    fn test_roles_type_exists() { let _type: Roles = Roles; }

    #[test]
    fn test_team_members_type_exists() { let _type: TeamMembers = TeamMembers; }

    #[test]
    fn test_teams_type_exists() { let _type: Teams = Teams; }

    #[test]
    fn test_user_roles_type_exists() { let _type: UserRoles = UserRoles; }

    #[test]
    fn test_user_sessions_type_exists() { let _type: UserSessions = UserSessions; }

    #[test]
    fn test_users_type_exists() { let _type: Users = Users; }
}
