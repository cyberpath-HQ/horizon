use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create api_key_usage_log table for B-08 audit logging
        manager
            .create_table(
                Table::create()
                    .table(ApiKeyUsageLog::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::Id)
                            .text()
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("cuid2(32, 'aklog_')")),
                    )
                    .col(ColumnDef::new(ApiKeyUsageLog::ApiKeyId).text().not_null())
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::Endpoint)
                            .string_len(512)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::Method)
                            .string_len(10)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::IpAddress)
                            .string_len(45)
                            .null(),
                    )
                    .col(ColumnDef::new(ApiKeyUsageLog::UserAgent).text().null())
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::StatusCode)
                            .small_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKeyUsageLog::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_key_usage_log_api_key_id")
                            .from(ApiKeyUsageLog::Table, ApiKeyUsageLog::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on api_key_id for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_usage_log_api_key_id")
                    .table(ApiKeyUsageLog::Table)
                    .col(ApiKeyUsageLog::ApiKeyId)
                    .to_owned(),
            )
            .await?;

        // Create index on created_at for time-range queries
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_usage_log_created_at")
                    .table(ApiKeyUsageLog::Table)
                    .col(ApiKeyUsageLog::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ApiKeyUsageLog::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ApiKeyUsageLog {
    Table,
    Id,
    ApiKeyId,
    Endpoint,
    Method,
    IpAddress,
    UserAgent,
    StatusCode,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
}
