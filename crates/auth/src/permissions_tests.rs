//! # Auth Permission and Role Tests
//!
//! Comprehensive unit tests for permission and role validation.

#[cfg(test)]
mod tests {
    use auth::permissions::{ApiKeyAction, Permission, TeamAction, UserAction};

    #[test]
    fn test_permission_string_parsing_users() {
        let perm = Permission::from_string("users:create");
        assert!(perm.is_some());
        assert_eq!(perm.unwrap(), Permission::Users(UserAction::Create));

        let perm = Permission::from_string("users:read");
        assert_eq!(perm.unwrap(), Permission::Users(UserAction::Read));

        let perm = Permission::from_string("users:update");
        assert_eq!(perm.unwrap(), Permission::Users(UserAction::Update));

        let perm = Permission::from_string("users:delete");
        assert_eq!(perm.unwrap(), Permission::Users(UserAction::Delete));
    }

    #[test]
    fn test_permission_string_parsing_teams() {
        let perm = Permission::from_string("teams:create");
        assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::Create));

        let perm = Permission::from_string("teams:members_read");
        assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::MembersRead));

        let perm = Permission::from_string("teams:members_add");
        assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::MembersAdd));

        let perm = Permission::from_string("teams:members_update");
        assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::MembersUpdate));

        let perm = Permission::from_string("teams:members_remove");
        assert_eq!(perm.unwrap(), Permission::Teams(TeamAction::MembersRemove));
    }

    #[test]
    fn test_permission_string_parsing_api_keys() {
        let perm = Permission::from_string("api_keys:create");
        assert_eq!(perm.unwrap(), Permission::ApiKeys(ApiKeyAction::Create));

        let perm = Permission::from_string("api_keys:rotate");
        assert_eq!(perm.unwrap(), Permission::ApiKeys(ApiKeyAction::Rotate));

        let perm = Permission::from_string("api_keys:usage_read");
        assert_eq!(perm.unwrap(), Permission::ApiKeys(ApiKeyAction::UsageRead));
    }

    #[test]
    fn test_permission_invalid_strings() {
        assert!(Permission::from_string("").is_none());
        assert!(Permission::from_string("invalid").is_none());
        assert!(Permission::from_string("invalid:action").is_none());
        assert!(Permission::from_string("users:invalid_action").is_none());
        assert!(Permission::from_string("teams:nonexistent").is_none());
        assert!(Permission::from_string("api_keys:bad_action").is_none());
    }

    #[test]
    fn test_permission_display() {
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
            format!("{}", Permission::ApiKeys(ApiKeyAction::Create)),
            "api_keys:create"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Read)),
            "api_keys:read"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Rotate)),
            "api_keys:rotate"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::Delete)),
            "api_keys:delete"
        );
        assert_eq!(
            format!("{}", Permission::ApiKeys(ApiKeyAction::UsageRead)),
            "api_keys:usage_read"
        );
    }

    #[test]
    fn test_permission_equality() {
        let perm1 = Permission::Users(UserAction::Create);
        let perm2 = Permission::Users(UserAction::Create);
        let perm3 = Permission::Users(UserAction::Read);

        assert_eq!(perm1, perm2);
        assert_ne!(perm1, perm3);
    }

    #[test]
    fn test_user_action_from_string() {
        assert_eq!(UserAction::from_string("create"), Some(UserAction::Create));
        assert_eq!(UserAction::from_string("read"), Some(UserAction::Read));
        assert_eq!(UserAction::from_string("update"), Some(UserAction::Update));
        assert_eq!(UserAction::from_string("delete"), Some(UserAction::Delete));
        assert_eq!(UserAction::from_string("invalid"), None);
    }

    #[test]
    fn test_team_action_from_string() {
        assert_eq!(TeamAction::from_string("create"), Some(TeamAction::Create));
        assert_eq!(TeamAction::from_string("read"), Some(TeamAction::Read));
        assert_eq!(
            TeamAction::from_string("members_read"),
            Some(TeamAction::MembersRead)
        );
        assert_eq!(
            TeamAction::from_string("members_add"),
            Some(TeamAction::MembersAdd)
        );
        assert_eq!(TeamAction::from_string("invalid"), None);
    }

    #[test]
    fn test_api_key_action_from_string() {
        assert_eq!(
            ApiKeyAction::from_string("create"),
            Some(ApiKeyAction::Create)
        );
        assert_eq!(ApiKeyAction::from_string("read"), Some(ApiKeyAction::Read));
        assert_eq!(
            ApiKeyAction::from_string("rotate"),
            Some(ApiKeyAction::Rotate)
        );
        assert_eq!(
            ApiKeyAction::from_string("usage_read"),
            Some(ApiKeyAction::UsageRead)
        );
        assert_eq!(ApiKeyAction::from_string("invalid"), None);
    }

    #[test]
    fn test_user_action_display() {
        assert_eq!(format!("{}", UserAction::Create), "create");
        assert_eq!(format!("{}", UserAction::Read), "read");
        assert_eq!(format!("{}", UserAction::Update), "update");
        assert_eq!(format!("{}", UserAction::Delete), "delete");
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

    #[test]
    fn test_api_key_action_display() {
        assert_eq!(format!("{}", ApiKeyAction::Create), "create");
        assert_eq!(format!("{}", ApiKeyAction::Read), "read");
        assert_eq!(format!("{}", ApiKeyAction::Update), "update");
        assert_eq!(format!("{}", ApiKeyAction::Delete), "delete");
        assert_eq!(format!("{}", ApiKeyAction::Rotate), "rotate");
        assert_eq!(format!("{}", ApiKeyAction::UsageRead), "usage_read");
    }

    #[test]
    fn test_permission_hash() {
        use std::collections::HashSet;

        let mut permissions = HashSet::new();
        let perm1 = Permission::Users(UserAction::Create);
        let perm2 = Permission::Users(UserAction::Create);
        let perm3 = Permission::Users(UserAction::Read);

        permissions.insert(perm1.clone());
        assert!(permissions.contains(&perm2));
        assert!(!permissions.contains(&perm3));

        permissions.insert(perm3);
        assert_eq!(permissions.len(), 2);
    }

    #[test]
    fn test_permission_clone() {
        let perm1 = Permission::Teams(TeamAction::MembersAdd);
        let perm2 = perm1.clone();
        assert_eq!(perm1, perm2);
    }

    #[test]
    fn test_permission_display() {
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
    }

    #[test]
    fn test_user_action_from_string() {
        assert_eq!(UserAction::from_string("create"), Some(UserAction::Create));
        assert_eq!(UserAction::from_string("read"), Some(UserAction::Read));
        assert_eq!(UserAction::from_string("update"), Some(UserAction::Update));
        assert_eq!(UserAction::from_string("delete"), Some(UserAction::Delete));
        assert_eq!(UserAction::from_string("invalid"), None);
    }

    #[test]
    fn test_team_action_from_string() {
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
        assert_eq!(TeamAction::from_string("invalid"), None);
    }

    #[test]
    fn test_api_key_action_from_string() {
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
        assert_eq!(ApiKeyAction::from_string("invalid"), None);
    }

    #[test]
    fn test_user_action_display() {
        assert_eq!(format!("{}", UserAction::Create), "create");
        assert_eq!(format!("{}", UserAction::Read), "read");
        assert_eq!(format!("{}", UserAction::Update), "update");
        assert_eq!(format!("{}", UserAction::Delete), "delete");
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

    #[test]
    fn test_api_key_action_display() {
        assert_eq!(format!("{}", ApiKeyAction::Create), "create");
        assert_eq!(format!("{}", ApiKeyAction::Read), "read");
        assert_eq!(format!("{}", ApiKeyAction::Rotate), "rotate");
        assert_eq!(format!("{}", ApiKeyAction::Delete), "delete");
        assert_eq!(format!("{}", ApiKeyAction::UsageRead), "usage_read");
    }
}
