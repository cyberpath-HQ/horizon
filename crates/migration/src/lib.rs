pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20250203_000001_create_users_table;
mod m20250203_000002_create_teams_table;
mod m20250203_000003_create_team_members_table;
mod m20250203_000004_add_teams_manager_fk;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20250203_000001_create_users_table::Migration),
            Box::new(m20250203_000002_create_teams_table::Migration),
            Box::new(m20250203_000003_create_team_members_table::Migration),
            Box::new(m20250203_000004_add_teams_manager_fk::Migration),
        ]
    }
}

/// Database connection helper for CLI usage
pub async fn connect_to_database(database_url: &str) -> Result<sea_orm::DatabaseConnection, sea_orm::DbErr> {
    sea_orm::Database::connect(database_url).await
}
