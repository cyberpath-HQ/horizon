pub use sea_orm_migration::prelude::*;

mod m20260203_000000_enable_pgcrypto;
mod m20260203_000001_create_users_table;
mod m20260203_0000025_add_teams_parent_fk;
mod m20260203_000002_create_teams_table;
mod m20260203_000003_create_team_members_table;
mod m20260203_000004_add_teams_manager_fk;
mod m20260203_000005_create_roles_table;
mod m20260203_000006_create_user_roles_table;
mod m20260203_000007_create_api_keys_table;
mod m20260203_000008_create_refresh_tokens_table;
mod m20260204_000009_create_user_sessions_table;
mod m20260205_000001_add_updated_at_triggers;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260203_000000_enable_pgcrypto::Migration),
            Box::new(m20260203_000001_create_users_table::Migration),
            Box::new(m20260203_000002_create_teams_table::Migration),
            Box::new(m20260203_0000025_add_teams_parent_fk::Migration),
            Box::new(m20260203_000003_create_team_members_table::Migration),
            Box::new(m20260203_000004_add_teams_manager_fk::Migration),
            Box::new(m20260203_000005_create_roles_table::Migration),
            Box::new(m20260203_000006_create_user_roles_table::Migration),
            Box::new(m20260203_000007_create_api_keys_table::Migration),
            Box::new(m20260203_000008_create_refresh_tokens_table::Migration),
            Box::new(m20260204_000009_create_user_sessions_table::Migration),
            Box::new(m20260205_000001_add_updated_at_triggers::Migration),
        ]
    }
}

/// Database connection helper for CLI usage
pub async fn connect_to_database(database_url: &str) -> Result<sea_orm::DatabaseConnection, sea_orm::DbErr> {
    sea_orm::Database::connect(database_url).await
}
