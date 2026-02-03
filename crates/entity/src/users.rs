//! Users Entity
//!
//! Represents system users with authentication and profile information.
//!
//! CUSTOMIZATION REGION START: user_entity_custom_types
//! This region is preserved during entity regeneration. Add custom types and implementations here.
//! CUSTOMIZATION REGION END

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, column_type = "Uuid")]
    pub id:                uuid::Uuid,
    pub email:             String,
    pub username:          String,
    pub password_hash:     String,
    pub totp_secret:       Option<String>,
    pub first_name:        Option<String>,
    pub last_name:         Option<String>,
    pub avatar_url:        Option<String>,
    pub status:            UserStatus,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at:     Option<chrono::DateTime<chrono::Utc>>,
    pub created_at:        chrono::DateTime<chrono::Utc>,
    pub updated_at:        chrono::DateTime<chrono::Utc>,
    pub deleted_at:        Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::team_members::Entity")]
    TeamMembers,
    #[sea_orm(has_many = "super::teams::Entity")]
    ManagedTeams,
}

impl Related<super::team_members::Entity> for Entity {
    fn to() -> RelationDef { Relation::TeamMembers.def() }
}

impl Related<super::teams::Entity> for Entity {
    fn to() -> RelationDef { Relation::ManagedTeams.def() }
}

impl ActiveModelBehavior for ActiveModel {}

/// User account status enumeration
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_status")]
pub enum UserStatus {
    /// Account is active and can be used
    #[sea_orm(string_value = "active")]
    Active,
    /// Account is inactive (user-disabled)
    #[sea_orm(string_value = "inactive")]
    Inactive,
    /// Account is suspended (admin action)
    #[sea_orm(string_value = "suspended")]
    Suspended,
    /// Account is pending email verification
    #[sea_orm(string_value = "pending_verification")]
    PendingVerification,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserStatus::Active => write!(f, "active"),
            UserStatus::Inactive => write!(f, "inactive"),
            UserStatus::Suspended => write!(f, "suspended"),
            UserStatus::PendingVerification => write!(f, "pending_verification"),
        }
    }
}

// CUSTOMIZATION REGION START: user_entity_methods
// Add custom methods and trait implementations here
// CUSTOMIZATION REGION END
