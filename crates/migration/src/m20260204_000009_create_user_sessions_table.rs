//! Migration: Create user sessions table
//!
//! This migration creates the user_sessions table for tracking active user sessions.
//! Sessions are linked to refresh tokens and track when they were created and last used.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserSessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserSessions::Id)
                            .text()
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("'h8ks3j2k9j3h8k2s3j4k5m6n7o8p9q0'")), // Default to super_admin CUID2
                    )
                    .col(ColumnDef::new(UserSessions::UserId).text().not_null())
                    .col(
                        ColumnDef::new(UserSessions::RefreshTokenId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserSessions::UserAgent).string().null())
                    .col(ColumnDef::new(UserSessions::IpAddress).string().null())
                    .col(
                        ColumnDef::new(UserSessions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(UserSessions::LastUsedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(UserSessions::RevokedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_sessions_user_id")
                            .from(UserSessions::Table, UserSessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_sessions_refresh_token_id")
                            .from(UserSessions::Table, UserSessions::RefreshTokenId)
                            .to(RefreshTokens::Table, RefreshTokens::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on user_id for efficient lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_user_id")
                    .table(UserSessions::Table)
                    .col(UserSessions::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on user_id and revoked_at for finding active sessions
        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_user_id_active")
                    .table(UserSessions::Table)
                    .col(UserSessions::UserId)
                    .col(UserSessions::RevokedAt)
                    .to_owned(),
            )
            .await?;

        // Create index on refresh_token_id for linking back to tokens
        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_refresh_token_id")
                    .table(UserSessions::Table)
                    .col(UserSessions::RefreshTokenId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserSessions::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum UserSessions {
    Table,
    Id,
    UserId,
    RefreshTokenId,
    UserAgent,
    IpAddress,
    CreatedAt,
    LastUsedAt,
    RevokedAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}

#[derive(Iden)]
enum RefreshTokens {
    Table,
    Id,
}
