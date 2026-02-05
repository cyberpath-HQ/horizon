use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create api_keys table
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(
                        uuid(ApiKeys::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("gen_random_uuid()")),
                    )
                    .col(uuid(ApiKeys::UserId).not_null())
                    .col(string(ApiKeys::Name).not_null())
                    .col(string(ApiKeys::KeyHash).not_null())
                    .col(string(ApiKeys::KeyPrefix).not_null())
                    .col(
                        ColumnDef::new(ApiKeys::Permissions)
                            .json()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .col(timestamp(ApiKeys::ExpiresAt).null())
                    .col(timestamp(ApiKeys::LastUsedAt).null())
                    .col(string(ApiKeys::LastUsedIp).null())
                    .col(
                        timestamp(ApiKeys::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(ApiKeys::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Add foreign key for user
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_api_keys_user_id")
                    .from(ApiKeys::Table, ApiKeys::UserId)
                    .to(Users::Table, Users::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // Create index for key lookup
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_api_keys_key_prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::KeyPrefix)
                    .to_owned(),
            )
            .await?;

        // Create index for user lookup
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_api_keys_user_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index for expiration
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_api_keys_expires_at")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ApiKeys::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum ApiKeys {
    Table,
    Id,
    UserId,
    Name,
    KeyHash,
    KeyPrefix,
    Permissions,
    ExpiresAt,
    LastUsedAt,
    LastUsedIp,
    CreatedAt,
    UpdatedAt,
}

// Reference to users table
#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
}
