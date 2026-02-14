pub use sea_orm_migration::prelude::*;

mod m00000000_000000_create_cuid_function;
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
mod m20260207_000001_add_mfa_and_lockout_columns;
mod m20260207_000002_create_api_key_usage_log_table;
mod m20260213_000001_create_system_settings_table;
mod m20260214_000001_alter_users_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m00000000_000000_create_cuid_function::Migration),
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
            Box::new(m20260207_000001_add_mfa_and_lockout_columns::Migration),
            Box::new(m20260207_000002_create_api_key_usage_log_table::Migration),
            Box::new(m20260213_000001_create_system_settings_table::Migration),
            Box::new(m20260214_000001_alter_users_table::Migration),
        ]
    }
}

/// Database connection helper for CLI usage
pub async fn connect_to_database(database_url: &str) -> Result<sea_orm::DatabaseConnection, sea_orm::DbErr> {
    sea_orm::Database::connect(database_url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrations_list() {
        let migrations = Migrator::migrations();
        assert_eq!(migrations.len(), 14);
        // Check that the migrations are in the correct order
        assert!(migrations[0].name().contains("create_cuid_function"));
        assert!(migrations[1].name().contains("create_users_table"));
        // Add more checks if needed
    }
}
