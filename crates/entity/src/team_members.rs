//! Team Members Entity
//!
//! Represents the relationship between users and teams, with role-based access control.
//!
//! CUSTOMIZATION REGION START: team_members_entity_custom_types
//! This region is preserved during entity regeneration. Add custom types and implementations here.
//! CUSTOMIZATION REGION END

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "team_members")]
pub struct Model {
    #[sea_orm(primary_key, column_type = "Uuid")]
    pub id:         uuid::Uuid,
    pub team_id:    uuid::Uuid,
    pub user_id:    uuid::Uuid,
    pub role:       TeamMemberRole,
    pub joined_at:  chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::teams::Entity",
        from = "Column::TeamId",
        to = "super::teams::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Team,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::teams::Entity> for Entity {
    fn to() -> RelationDef { Relation::Team.def() }
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef { Relation::User.def() }
}

impl ActiveModelBehavior for ActiveModel {}

/// Team member role enumeration
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "team_member_role")]
pub enum TeamMemberRole {
    /// Full control over team and can manage members
    #[sea_orm(string_value = "owner")]
    Owner,
    /// Administrative control, can manage members and settings
    #[sea_orm(string_value = "admin")]
    Admin,
    /// Can view and edit team resources
    #[sea_orm(string_value = "member")]
    Member,
    /// Read-only access to team resources
    #[sea_orm(string_value = "viewer")]
    Viewer,
}

impl std::fmt::Display for TeamMemberRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeamMemberRole::Owner => write!(f, "owner"),
            TeamMemberRole::Admin => write!(f, "admin"),
            TeamMemberRole::Member => write!(f, "member"),
            TeamMemberRole::Viewer => write!(f, "viewer"),
        }
    }
}

// CUSTOMIZATION REGION START: team_members_entity_methods
// Add custom methods and trait implementations here
// CUSTOMIZATION REGION END
