//! Migration: Add automatic updated_at timestamp triggers
//!
//! This migration adds PostgreSQL triggers to automatically update the `updated_at`
//! column whenever a row is modified. This ensures data integrity without requiring
//! application-level timestamp management.
//!
//! Tables affected:
//! - users
//! - roles
//! - user_roles
//! - teams
//! - team_members
//! - refresh_tokens
//! - api_keys
//! - user_sessions

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the trigger function that updates updated_at column
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE OR REPLACE FUNCTION update_updated_at_column()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = CURRENT_TIMESTAMP;
                    RETURN NEW;
                END;
                $$ language 'plpgsql';
            "#,
            )
            .await?;

        // Apply trigger to each table with updated_at
        let tables = [
            "users",
            "roles",
            "user_roles",
            "teams",
            "team_members",
            "refresh_tokens",
            "api_keys",
            "user_sessions",
        ];

        for table in tables {
            let trigger_name = format!("update_{}_updated_at", table);
            let sql = format!(
                "DROP TRIGGER IF EXISTS {} ON {}; CREATE TRIGGER {} BEFORE UPDATE ON {} FOR EACH ROW EXECUTE FUNCTION \
                 update_updated_at_column()",
                trigger_name, table, trigger_name, table
            );
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove triggers from all tables
        let tables = [
            "users",
            "roles",
            "user_roles",
            "teams",
            "team_members",
            "refresh_tokens",
            "api_keys",
            "user_sessions",
        ];

        for table in tables {
            let trigger_name = format!("update_{}_updated_at", table);
            let sql = format!("DROP TRIGGER IF EXISTS {} ON {}", trigger_name, table);
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        // Remove the trigger function
        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS update_updated_at_column()")
            .await?;

        Ok(())
    }
}
