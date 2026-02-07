//! Migration: Create refresh tokens table
//!
//! This migration creates the refresh_tokens table for storing JWT refresh tokens.
//! Refresh tokens are used to obtain new access tokens without re-authentication.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshTokens::Id)
                            .text()
                            .primary_key()
                            .default(Expr::cust("cuid2(32, 'rtok_')")),
                    )
                    .col(ColumnDef::new(RefreshTokens::UserId).text().not_null())
                    .col(
                        ColumnDef::new(RefreshTokens::TokenHash)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::RevokedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_tokens_user_id")
                            .from(RefreshTokens::Table, RefreshTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for faster lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_user_id")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on expires_at for cleanup queries
        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_tokens_expires_at")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RefreshTokens::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum RefreshTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    ExpiresAt,
    RevokedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}
