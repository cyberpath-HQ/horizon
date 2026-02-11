//! Migration: Add automatic updated_at timestamp triggers
//!
//! This migration adds PostgreSQL triggers to automatically update the `updated_at`
//! column whenever a row is modified. This ensures data integrity without requiring
//! application-level timestamp management.
//!
//! This migration dynamically discovers ALL tables in the 'public' schema that have
//! an `updated_at` column and applies the trigger to each one. This ensures the
//! trigger is applied to any new tables added in future migrations.
//!
//! IMPORTANT: This migration MUST run LAST to ensure it applies to all tables
//! in their final state.

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

        // Dynamically apply triggers to all tables with updated_at column using DO block
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DO $$
                DECLARE
                    tbl text;
                    trg text;
                BEGIN
                    FOR tbl IN
                        SELECT table_name FROM information_schema.columns
                        WHERE table_schema = 'public' AND column_name = 'updated_at'
                        ORDER BY table_name
                    LOOP
                        trg := 'update_' || tbl || '_updated_at';
                        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trg, tbl);
                        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()', trg, tbl);
                        RAISE NOTICE 'Applied updated_at trigger to table: %', tbl;
                    END LOOP;
                END $$;
            "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Dynamically remove triggers from all tables with updated_at column using DO block
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DO $$
                DECLARE
                    tbl text;
                    trg text;
                BEGIN
                    FOR tbl IN
                        SELECT c.table_name FROM information_schema.columns c
                        JOIN information_schema.tables t ON c.table_name = t.table_name AND c.table_schema = t.table_schema
                         WHERE c.table_schema = 'public'
                           AND c.column_name = 'updated_at'
                           AND t.table_type = 'BASE TABLE'
                     LOOP
                        trg := 'update_' || tbl || '_updated_at';
                        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trg, tbl);
                    END LOOP;
                END $$;
            "#,
            )
            .await?;

        // Remove the trigger function
        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS update_updated_at_column()")
            .await?;

        Ok(())
    }
}
