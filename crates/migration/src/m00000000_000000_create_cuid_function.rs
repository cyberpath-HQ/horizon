use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Enable pgcrypto extension for SHA3-512
        manager
            .get_connection()
            .execute_unprepared("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            .await?;

        // Create the counter sequence with random initialization
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE SEQUENCE IF NOT EXISTS cuid2_counter_seq
                    START WITH 1
                    INCREMENT BY 1
                    MINVALUE 0
                    MAXVALUE 476782367
                    CYCLE;
                "#,
            )
            .await?;

        // Randomly initialize the counter (matches CUID2 spec)
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DO $$
                BEGIN
                    PERFORM setval('cuid2_counter_seq', 
                        floor(random() * 476782367)::bigint, false);
                END $$;
                "#,
            )
            .await?;

        // Create all CUID2 functions
        manager
            .get_connection()
            .execute_unprepared(include_str!("./cuid2_functions.sql"))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP FUNCTION IF EXISTS cuid2(integer, text) CASCADE;
                DROP FUNCTION IF EXISTS cuid2_slug(text) CASCADE;
                DROP FUNCTION IF EXISTS is_cuid2(text, integer, text) CASCADE;
                DROP FUNCTION IF EXISTS cuid2_prefixed(text, integer) CASCADE;
                DROP FUNCTION IF EXISTS bytes_to_base36(bytea, integer) CASCADE;
                DROP FUNCTION IF EXISTS base36_encode(bigint) CASCADE;
                DROP FUNCTION IF EXISTS generate_entropy(integer) CASCADE;
                DROP FUNCTION IF EXISTS generate_fingerprint() CASCADE;
                DROP SEQUENCE IF EXISTS cuid2_counter_seq CASCADE;
                "#,
            )
            .await?;

        Ok(())
    }
}
