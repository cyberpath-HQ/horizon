use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Enable pgcrypto extension for gen_random_uuid()
        // This must be created at database level, not schema level
        manager
            .get_connection()
            .execute_unprepared("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop pgcrypto extension
        manager
            .get_connection()
            .execute_unprepared("DROP EXTENSION IF EXISTS pgcrypto")
            .await?;

        Ok(())
    }
}
