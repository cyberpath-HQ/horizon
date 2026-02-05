//! `SeaORM` Entity for user_sessions
//!
//! Tracks active user sessions linked to refresh tokens

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id:               Uuid,
    pub user_id:          Uuid,
    pub refresh_token_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address:       Option<String>,
    pub created_at:       DateTime,
    pub last_used_at:     DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at:       Option<DateTime>,
}

impl ActiveModelBehavior for ActiveModel {}
