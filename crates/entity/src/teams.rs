//! Teams Entity
//!
//! Represents organizational teams with hierarchical structure support.
//!
//! CUSTOMIZATION REGION START: teams_entity_custom_types
//! This region is preserved during entity regeneration. Add custom types and implementations here.
//! CUSTOMIZATION REGION END

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "teams")]
pub struct Model {
    #[sea_orm(primary_key, column_type = "Uuid")]
    pub id:             uuid::Uuid,
    pub name:           String,
    pub slug:           String,
    pub description:    Option<String>,
    pub parent_team_id: Option<uuid::Uuid>,
    pub manager_id:     uuid::Uuid,
    pub created_at:     chrono::DateTime<chrono::Utc>,
    pub updated_at:     chrono::DateTime<chrono::Utc>,
    pub deleted_at:     Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::teams::Entity",
        from = "Column::ParentTeamId",
        to = "super::teams::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ParentTeam,
    #[sea_orm(has_many = "super::teams::Entity")]
    ChildTeams,
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::ManagerId",
        to = "super::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Restrict"
    )]
    Manager,
    #[sea_orm(has_many = "super::team_members::Entity")]
    TeamMembers,
}

impl Related<super::teams::Entity> for Entity {
    fn to() -> RelationDef { Relation::ChildTeams.def() }
}

impl Related<super::users::Entity> for Entity {
    fn to() -> RelationDef { Relation::Manager.def() }
}

impl Related<super::team_members::Entity> for Entity {
    fn to() -> RelationDef { Relation::TeamMembers.def() }
}

impl ActiveModelBehavior for ActiveModel {}

// CUSTOMIZATION REGION START: teams_entity_methods
// Add custom methods and trait implementations here
// CUSTOMIZATION REGION END
