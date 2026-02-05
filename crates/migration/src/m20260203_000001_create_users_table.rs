use sea_orm_migration::{prelude::*, schema::*, sea_query::extension::postgres::Type};
use sea_query::Alias;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create enum type first
        manager
            .create_type(
                Type::create()
                    .as_enum(Alias::new("user_status"))
                    .values(["active", "inactive", "suspended", "pending_verification"])
                    .to_owned(),
            )
            .await?;

        // Create users table using schema helpers
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        text(Users::Id)
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("'h8ks3j2k9j3h8k2s3j4k5m6n7o8p9q0'")), // Default to super_admin CUID2
                    )
                    .col(string(Users::Email).not_null().unique_key())
                    .col(string(Users::Username).not_null().unique_key())
                    .col(string(Users::PasswordHash).not_null())
                    .col(string(Users::TotpSecret).null())
                    .col(string(Users::FirstName).null())
                    .col(string(Users::LastName).null())
                    .col(string(Users::AvatarUrl).null())
                    .col(
                        ColumnDef::new(Users::Status)
                            .custom(Alias::new("user_status"))
                            .not_null()
                            .default(Expr::cust("'pending_verification'")),
                    )
                    .col(timestamp(Users::EmailVerifiedAt).null())
                    .col(timestamp(Users::LastLoginAt).null())
                    .col(
                        timestamp(Users::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Users::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp(Users::DeletedAt).null())
                    .to_owned(),
            )
            .await?;

        // Create index for status
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_status")
                    .table(Users::Table)
                    .col(Users::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(Alias::new("user_status")).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    Username,
    PasswordHash,
    TotpSecret,
    FirstName,
    LastName,
    AvatarUrl,
    Status,
    EmailVerifiedAt,
    LastLoginAt,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}
